//! `zkminer-builder-check [--memory-bytes N] MODULE.wasm...`: puts builder modules through exactly
//! the pre-pass the runner applies (the ABI v1 profile, the imports and exports, the structural
//! limits and the compile-cost budget) and prints each one's compile-cost estimate. The SDK's
//! `build-reproducible.sh` runs it on every module it builds.
//!
//! `--memory-bytes` is the `maxBuilderMemoryBytes` the module's initial memory must fit (default: the
//! hard ceiling, 1 GiB). Exits 0 when every module passes, else with the first failure's runner exit
//! code (INVALID_MODULE or UNKNOWN_IMPORT), or 2 on a usage or I/O error.

use std::process::ExitCode;

use zkminer_witness::envelope::HARD_MAX_BUILDER_MEMORY_BYTES;
use zkminer_witness_builder::cost::COMPILE_BUDGET_NS;
use zkminer_witness_builder::prepass;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1).peekable();
    let mut memory = HARD_MAX_BUILDER_MEMORY_BYTES;
    if args.peek().map(String::as_str) == Some("--memory-bytes") {
        args.next();
        match args.next().and_then(|v| v.parse().ok()) {
            Some(m) => memory = m,
            None => return usage(),
        }
    }
    let paths: Vec<String> = args.collect();
    if paths.is_empty() || paths.iter().any(|p| p.starts_with('-')) {
        return usage();
    }
    let mut status = 0u8;
    for path in &paths {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("{path}: {e}");
                return ExitCode::from(2);
            }
        };
        match prepass(&bytes, memory) {
            Ok(info) => {
                let c = info.cost;
                let (term, _, ns) = c.priced_terms().into_iter().max_by_key(|t| t.2).unwrap_or(("", 0, 0));
                println!(
                    "{path}: ok: {} bytes, {} functions, {} KiB initial memory; compile cost {:.1} ms of {} ms \
                     (largest: {term}, {:.1} ms); max nesting {}, max params + results {}",
                    bytes.len(),
                    info.functions,
                    info.initial_memory_bytes / 1024,
                    c.estimate_ns() as f64 / 1e6,
                    COMPILE_BUDGET_NS / 1_000_000,
                    ns as f64 / 1e6,
                    c.max_depth,
                    c.max_type_arity,
                );
            }
            Err(e) => {
                eprintln!("{path}: REFUSED: {e}");
                if status == 0 {
                    status = u8::try_from(e.exit_code()).unwrap_or(1);
                }
            }
        }
    }
    ExitCode::from(status)
}

fn usage() -> ExitCode {
    eprintln!("usage: zkminer-builder-check [--memory-bytes N] MODULE.wasm...");
    ExitCode::from(2)
}
