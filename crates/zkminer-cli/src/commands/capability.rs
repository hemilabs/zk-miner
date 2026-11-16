//! What this host can prove, card by card: the table `zkminer run` prints at startup and
//! `zkminer doctor` prints on demand.
//!
//! Before it, a card that could not take part said so only at debug level or in a `warn` line that
//! never reached the dashboard: a missing or non-executable worker binary was skipped silently, a
//! 12 GB card idled on both zkVMs with no reason given, and OpenVM was started though it is never
//! mined.

use std::collections::HashMap;
use zkminer_prover::dispatcher::{SlotCheck, SlotOutcome, WorkerSurvey};
use zkminer_prover_protocol::{BACKEND_OPENVM, BACKEND_RISC0, BACKEND_SP1};

/// How one zkVM stands on one card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// "GPU 0: NVIDIA GeForce RTX 4090 (24.0 GiB)", or "this machine" for a worker with no card.
    pub card: String,
    /// "RISC Zero", "SP1", "OpenVM".
    pub zkvm: &'static str,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// It proves here (what it proves at, e.g. "segment size 2^20").
    Ready(String),
    /// Its worker runs, but it gets no jobs here (why, and what changes that).
    Idle(String),
    /// No worker for it here (why, and what changes that).
    Missing(String),
}

impl Verdict {
    pub fn is_ready(&self) -> bool {
        matches!(self, Verdict::Ready(_))
    }
}

/// The risc0 segment sizes the operator set, by device id (`[prover.risc0_job_po2]`).
pub type Risc0Sizes = HashMap<String, u8>;

fn zkvm_name(backend: &str) -> &'static str {
    match backend {
        BACKEND_RISC0 => "RISC Zero",
        BACKEND_SP1 => "SP1",
        BACKEND_OPENVM => "OpenVM",
        _ => "?",
    }
}

const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

fn card_label(gpu_tag: &str, index: Option<u32>, name: Option<&str>, vram: Option<u64>) -> String {
    if gpu_tag == "generic" || index.is_none() {
        return "this machine".to_string();
    }
    let vendor = match gpu_tag {
        "cuda" => "GPU",
        "rocm" => "AMD GPU",
        "intel" => "Intel GPU",
        other => other,
    };
    let mut label = format!("{vendor} {}", index.unwrap_or(0));
    if let Some(n) = name {
        label.push_str(&format!(": {n}"));
    }
    if let Some(v) = vram {
        label.push_str(&format!(" ({:.1} GiB)", v as f64 / GIB));
    }
    label
}

/// Whether the miner mines OpenVM jobs (`ZKMINER_ENABLE_OPENVM=1`; see `resolve_backend`).
pub fn openvm_enabled() -> bool {
    std::env::var("ZKMINER_ENABLE_OPENVM").ok().as_deref() == Some("1")
}

/// The verdict for a slot whose worker runs (or would): whether jobs will reach it.
fn running_verdict(
    slot: &SlotCheck,
    risc0_sizes: &Risc0Sizes,
    suite: Option<&zkminer_prover::benchmark::BenchmarkSuite>,
) -> Verdict {
    match slot.backend.as_str() {
        BACKEND_RISC0 => {
            let device = slot.device_id();
            let row = suite.and_then(|s| {
                s.device_benchmarks
                    .iter()
                    .find(|d| d.device_id == device && d.prover_backend == BACKEND_RISC0)
            });
            let over = risc0_sizes.get(&device).copied();
            match zkminer_prover::benchmark::risc0_job_po2(over, row, slot.vram_bytes) {
                Some(po2) => Verdict::Ready(format!(
                    "segment size 2^{po2}{}",
                    match (over, row.is_some_and(|r| !r.po2_samples.is_empty())) {
                        (Some(_), _) => " (set in the config)",
                        (None, true) => " (calibrated)",
                        (None, false) => "",
                    }
                )),
                None => Verdict::Idle(format!(
                    "no segment size for a card under {:.0} GiB, so it proves no RISC Zero job. \
                     Set a smaller one (`[prover.risc0_job_po2]` {device} = 19) or run `zkminer \
                     benchmark --calibrate` with the miner stopped.",
                    zkminer_prover::benchmark::RISC0_JOB_MIN_VRAM_BYTES as f64 / GIB
                )),
            }
        }
        BACKEND_SP1 => {
            let floor =
                zkminer_prover::discovery::min_available_vram_bytes_for_backend(BACKEND_SP1);
            match (floor, slot.vram_bytes) {
                (Some(need), Some(have)) if have < need => Verdict::Idle(format!(
                    "SP1 work needs {:.1} GiB of VRAM free and this card has {:.1} GiB in all, so \
                     it gets none. {}=<MiB> lowers the bar, at the risk of running out part-way \
                     through a claimed job.",
                    need as f64 / GIB,
                    have as f64 / GIB,
                    zkminer_prover::discovery::MIN_AVAILABLE_VRAM_MB_ENV,
                )),
                (Some(need), _) => Verdict::Ready(format!(
                    "when {:.1} GiB of its VRAM is free",
                    need as f64 / GIB
                )),
                (None, _) => Verdict::Ready(String::new()),
            }
        }
        BACKEND_OPENVM if !openvm_enabled() => Verdict::Idle(
            "OpenVM is experimental and not mined; its worker only takes memory. Remove \
             zkminer-prove-openvm*, or set ZKMINER_ENABLE_OPENVM=1 to mine it."
                .to_string(),
        ),
        _ => Verdict::Ready(String::new()),
    }
}

/// The table: a row per card and zkVM this miner serves (OpenVM only where its worker was found),
/// plus a row per worker with no card. `served` are the backends the miner claims jobs for.
pub fn rows(
    survey: &WorkerSurvey,
    served: &[&str],
    risc0_sizes: &Risc0Sizes,
    suite: Option<&zkminer_prover::benchmark::BenchmarkSuite>,
) -> Vec<Row> {
    let mut rows = Vec::new();
    let searched = |backend: &str, gpu_tag: &str| -> String {
        let names = zkminer_prover::discovery::worker_file_names(backend, gpu_tag).join(" or ");
        let dirs: Vec<String> = survey
            .searched
            .iter()
            .map(|d| d.display().to_string())
            .collect();
        let mut text = format!("looked for {names} in {} and PATH", dirs.join(", "));
        let unusable =
            zkminer_prover::discovery::non_executable_workers(backend, gpu_tag, &survey.searched);
        if let Some(p) = unusable.first() {
            text.push_str(&format!(
                "; {} is there but not executable (chmod +x it)",
                p.display()
            ));
        }
        text
    };
    let verdict_of = |slot: &SlotCheck| match &slot.outcome {
        SlotOutcome::Started | SlotOutcome::WouldStart => running_verdict(slot, risc0_sizes, suite),
        SlotOutcome::Refused(why) => Verdict::Missing(format!("not started: {why}")),
        SlotOutcome::Failed(e) => Verdict::Missing(format!("its worker failed to start: {e}")),
    };
    for gpu in &survey.gpus {
        let vram = survey
            .slots
            .iter()
            .find(|s| s.gpu_tag == gpu.gpu_tag && s.device_index == Some(gpu.device_index))
            .and_then(|s| s.vram_bytes);
        let card = card_label(&gpu.gpu_tag, Some(gpu.device_index), Some(&gpu.name), vram);
        let mut backends: Vec<&str> = served.to_vec();
        let has_openvm = survey.slots.iter().any(|s| {
            s.backend == BACKEND_OPENVM
                && s.gpu_tag == gpu.gpu_tag
                && s.device_index == Some(gpu.device_index)
        });
        if has_openvm && !backends.contains(&BACKEND_OPENVM) {
            backends.push(BACKEND_OPENVM);
        }
        for backend in backends {
            let slot = survey.slots.iter().find(|s| {
                s.backend == backend
                    && s.gpu_tag == gpu.gpu_tag
                    && s.device_index == Some(gpu.device_index)
            });
            let verdict = match slot {
                Some(slot) => verdict_of(slot),
                // A worker with no card (generic, or an explicit binary) may serve this card.
                None if survey
                    .slots
                    .iter()
                    .any(|s| s.backend == backend && s.device_index.is_none()) =>
                {
                    continue
                }
                None => Verdict::Missing(format!(
                    "no {} worker for this card: {}",
                    zkvm_name(backend),
                    searched(backend, &gpu.gpu_tag)
                )),
            };
            rows.push(Row {
                card: card.clone(),
                zkvm: zkvm_name(backend),
                verdict,
            });
        }
    }
    for slot in survey.slots.iter().filter(|s| s.device_index.is_none()) {
        rows.push(Row {
            card: card_label(&slot.gpu_tag, None, None, None),
            zkvm: zkvm_name(&slot.backend),
            verdict: verdict_of(slot),
        });
    }
    if survey.gpus.is_empty() && !survey.slots.iter().any(|s| s.device_index.is_none()) {
        rows.push(Row {
            card: "this machine".to_string(),
            zkvm: "any",
            verdict: Verdict::Missing(
                "no GPU found (nvidia-smi, the amdgpu driver and the Intel xe driver were asked) \
                 and no CPU worker configured"
                    .to_string(),
            ),
        });
    }
    rows
}

/// One line per row, e.g. "  GPU 0: RTX 4090 (24.0 GiB) · SP1: ready — when 15.2 GiB … is free".
pub fn lines(rows: &[Row]) -> Vec<String> {
    rows.iter()
        .map(|r| {
            let (word, why) = match &r.verdict {
                Verdict::Ready(why) => ("ready", why),
                Verdict::Idle(why) => ("IDLE", why),
                Verdict::Missing(why) => ("NOT AVAILABLE", why),
            };
            if why.is_empty() {
                format!("{} · {}: {word}", r.card, r.zkvm)
            } else {
                format!("{} · {}: {word} — {why}", r.card, r.zkvm)
            }
        })
        .collect()
}

/// Whether anything on this host can prove a job the miner claims.
pub fn anything_proves(rows: &[Row]) -> bool {
    rows.iter()
        .any(|r| r.verdict.is_ready() && r.zkvm != zkvm_name(BACKEND_OPENVM))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use zkminer_prover::discovery::DetectedGpu;

    fn gpu(index: u32, name: &str) -> DetectedGpu {
        DetectedGpu {
            gpu_tag: "cuda".into(),
            device_index: index,
            pci_bus_id: format!("0000:0{index}:00.0"),
            name: name.into(),
            compute_cap: Some((8, 9)),
        }
    }

    fn slot(backend: &str, index: u32, vram_gib: u64, outcome: SlotOutcome) -> SlotCheck {
        SlotCheck {
            backend: backend.into(),
            gpu_tag: "cuda".into(),
            device_index: Some(index),
            gpu_name: None,
            vram_bytes: Some(vram_gib * 1024 * 1024 * 1024),
            path: PathBuf::from("/x"),
            outcome,
        }
    }

    fn verdict<'a>(rows: &'a [Row], card: &str, zkvm: &str) -> &'a Verdict {
        &rows
            .iter()
            .find(|r| r.card.starts_with(card) && r.zkvm == zkvm)
            .unwrap_or_else(|| panic!("no {card} {zkvm} row in {rows:#?}"))
            .verdict
    }

    /// A 24 GiB card proves both; a 12 GiB card runs both workers and proves neither, and says why
    /// and what to change.
    #[test]
    fn a_12_gib_card_says_why_it_proves_nothing() {
        let survey = WorkerSurvey {
            gpus: vec![gpu(0, "RTX 4090"), gpu(1, "RTX 4070")],
            slots: vec![
                slot(BACKEND_RISC0, 0, 24, SlotOutcome::Started),
                slot(BACKEND_SP1, 0, 24, SlotOutcome::Started),
                slot(BACKEND_RISC0, 1, 12, SlotOutcome::Started),
                slot(BACKEND_SP1, 1, 12, SlotOutcome::Started),
            ],
            searched: vec![],
        };
        let rows = rows(
            &survey,
            &[BACKEND_RISC0, BACKEND_SP1],
            &HashMap::new(),
            None,
        );
        assert_eq!(
            verdict(&rows, "GPU 0", "RISC Zero"),
            &Verdict::Ready("segment size 2^20".into())
        );
        assert!(verdict(&rows, "GPU 0", "SP1").is_ready());
        let Verdict::Idle(why) = verdict(&rows, "GPU 1", "RISC Zero") else {
            panic!("{rows:#?}")
        };
        assert!(why.contains("gpu1 = 19"), "{why}");
        let Verdict::Idle(why) = verdict(&rows, "GPU 1", "SP1") else {
            panic!("{rows:#?}")
        };
        assert!(why.contains("ZKMINER_MIN_AVAILABLE_VRAM_MB"), "{why}");
        assert!(anything_proves(&rows));
        // A size set for the card makes RISC Zero prove there.
        let sizes = HashMap::from([("gpu1".to_string(), 19u8)]);
        let rows = super::rows(&survey, &[BACKEND_RISC0, BACKEND_SP1], &sizes, None);
        assert_eq!(
            verdict(&rows, "GPU 1", "RISC Zero"),
            &Verdict::Ready("segment size 2^19 (set in the config)".into())
        );
    }

    /// A card with no worker says where the binary was looked for; a refused one says why.
    #[test]
    fn missing_and_refused_workers_say_why() {
        let survey = WorkerSurvey {
            gpus: vec![gpu(0, "RTX 5080")],
            slots: vec![slot(
                BACKEND_SP1,
                0,
                16,
                SlotOutcome::Refused("sp1 is known to fault on this card".into()),
            )],
            searched: vec![PathBuf::from("/opt/zk")],
        };
        let rows = rows(
            &survey,
            &[BACKEND_RISC0, BACKEND_SP1],
            &HashMap::new(),
            None,
        );
        let Verdict::Missing(why) = verdict(&rows, "GPU 0", "RISC Zero") else {
            panic!("{rows:#?}")
        };
        assert!(why.contains("zkminer-prove-risc0-cuda"), "{why}");
        assert!(why.contains("/opt/zk"), "{why}");
        let Verdict::Missing(why) = verdict(&rows, "GPU 0", "SP1") else {
            panic!("{rows:#?}")
        };
        assert!(why.contains("known to fault"), "{why}");
        assert!(!anything_proves(&rows));
        assert!(lines(&rows).iter().all(|l| l.contains("NOT AVAILABLE")));
    }

    /// OpenVM shows only where its worker runs, as idle unless enabled, and never counts as proving.
    #[test]
    fn openvm_is_labelled_not_mined() {
        if openvm_enabled() {
            return;
        }
        let survey = WorkerSurvey {
            gpus: vec![gpu(0, "RTX 4090")],
            slots: vec![slot(BACKEND_OPENVM, 0, 24, SlotOutcome::Started)],
            searched: vec![],
        };
        let rows = rows(&survey, &[BACKEND_RISC0], &HashMap::new(), None);
        assert!(
            matches!(verdict(&rows, "GPU 0", "OpenVM"), Verdict::Idle(w) if w.contains("not mined"))
        );
        assert!(!anything_proves(&rows));
    }

    #[test]
    fn no_gpu_and_no_cpu_worker_is_one_row() {
        let rows = rows(
            &WorkerSurvey::default(),
            &[BACKEND_RISC0],
            &HashMap::new(),
            None,
        );
        assert_eq!(rows.len(), 1);
        assert!(!anything_proves(&rows));
    }
}
