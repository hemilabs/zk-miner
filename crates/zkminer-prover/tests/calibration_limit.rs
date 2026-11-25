//! A calibration run stopped at the sweep's limit (`benchmark::calibration_run_limit`), end to end
//! through `WorkerPool` and the mock worker: answered as a size that does not fit, logged once as
//! that, never as a proving timeout. Its own test binary, so the log it reads is its own.
//!
//! Run with: `cargo test -p zkminer-prover --features testing --test calibration_limit`
#![cfg(feature = "testing")]

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zkminer_prover::dispatcher::{CalibrationTooSlow, TestCard, WorkerPool};

const MIB: u64 = 1024 * 1024;
/// An RTX 5080.
const TOTAL_MIB: u64 = 16_303;
const KEY: &str = "risc0:cuda:0";

/// Everything logged in this process, as text.
#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<u8>>>);

impl Write for Log {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Log {
    fn install() -> Self {
        let log = Log::default();
        let writer = log.clone();
        tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish(),
        )
        .expect("the only subscriber in this binary");
        log
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

fn pool(knobs: &[(&str, &str)]) -> WorkerPool {
    let mut env: HashMap<String, String> = knobs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    env.insert("MOCK_BACKEND".into(), "risc0".into());
    let mut pool = WorkerPool::new(HashMap::new(), Vec::new(), None);
    pool.insert_test_worker(
        KEY,
        "risc0",
        PathBuf::from(env!("CARGO_BIN_EXE_mock-worker")),
        env,
    )
    .expect("spawn the mock worker");
    pool.test_set_card_identity(
        KEY,
        "cuda",
        Some("0000:01:00.0"),
        Some("NVIDIA GeForce RTX 5080"),
        Some(TOTAL_MIB * MIB),
    );
    pool.test_set_cards(
        KEY,
        vec![Some(TestCard {
            total_mib: TOTAL_MIB,
            reserved_mib: 272,
            ..Default::default()
        })],
    );
    pool
}

#[test]
fn a_calibration_run_past_its_limit_is_stopped_as_too_slow_and_logged_once_as_that() {
    let log = Log::install();
    let started = Instant::now();
    let e = pool(&[("MOCK_HANG_ON", "calibrate")])
        .calibrate_slot_po2_within(KEY, 21, Some(Duration::from_secs(2)))
        .expect_err("the run hangs past its limit");
    let slow = e
        .downcast_ref::<CalibrationTooSlow>()
        .unwrap_or_else(|| panic!("typed as too slow: {e:#}"));
    assert_eq!((slow.slot_key.as_str(), slow.po2), (KEY, 21));
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "stopped at its limit"
    );
    assert_eq!(
        e.to_string(),
        "risc0:cuda:0: po2 21 stopped after 2 s: slower than 3x the fastest size so far, treated \
         as not fitting this card (on Windows, memory that does not fit a card goes to system \
         memory instead of failing)"
    );
    let text = log.text();
    assert!(!text.contains("Proving timeout"), "{text}");
    assert!(!text.contains("ERROR"), "{text}");
    assert!(
        text.contains("run past its 2s limit"),
        "the watchdog stopped it: {text}"
    );

    // A run inside its limit is unaffected.
    let sample = pool(&[])
        .calibrate_slot_po2_within(KEY, 20, Some(Duration::from_secs(60)))
        .expect("a run inside its limit is unaffected");
    assert_eq!(sample.po2, 20);
}
