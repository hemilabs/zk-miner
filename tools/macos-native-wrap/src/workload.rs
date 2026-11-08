//! Execution-only fixture sizing; collect segment sizes and the unchanged claim.
use anyhow::{ensure, Result};
use risc0_zkvm::{sha::Digestible, ExecutorEnv, ExecutorImpl, SimpleSegmentRef};
use std::{fs, path::Path, time::Instant};

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(args.len() == 6, "usage: hemi-workload-execute PROGRAM INPUT PO2 MAX_GUEST_CYCLES NEW_OUTPUT");
    ensure!(!Path::new(&args[5]).exists(), "output exists");
    let program = fs::read(&args[1])?;
    let input = fs::read(&args[2])?;
    let po2: u32 = args[3].parse()?;
    ensure!((13..=20).contains(&po2), "sizing po2 must be 13..=20");
    let limit: u64 = args[4].parse()?;
    ensure!((1..=67_108_864).contains(&limit), "invalid sizing cycle limit");
    let env = ExecutorEnv::builder().write_slice(&input).segment_limit_po2(po2)
        .session_limit(Some(limit)).build()?;
    let started = Instant::now();
    let mut executor = ExecutorImpl::from_elf(env, &program)?;
    let mut segments = Vec::new();
    let session = executor.run_with_callback(|segment| {
        segments.push(segment.po2());
        Ok(Box::new(SimpleSegmentRef::new(segment)))
    })?;
    let report = serde_json::json!({"segment_po2":segments,"guest_cycles":session.user_cycles,
        "total_cycles":session.total_cycles,"paging_cycles":session.paging_cycles,
        "reserved_cycles":session.reserved_cycles,"claim_digest":session.claim()?.digest().to_string(),
        "journal_hex":hex::encode(session.journal.as_ref().map(|j| j.bytes.as_slice()).unwrap_or_default()),
        "seconds":started.elapsed().as_secs_f64()});
    fs::write(&args[5], serde_json::to_vec_pretty(&report)?)?;
    println!("{report}");
    Ok(())
}
