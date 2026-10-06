//! Harness self-tests and a smoke table for `zkminer` with no workers installed.
#![cfg(unix)]

use std::panic::{catch_unwind, AssertUnwindSafe};

use rstest::rstest;
use zkminer_e2e::{run_case, Case, Expect, Sandbox};

fn benchmark_json_without_devices(v: &serde_json::Value) -> Result<(), String> {
    if !v["cpu_info"].is_string() {
        return Err(format!("cpu_info should be a string, got {}", v["cpu_info"]));
    }
    match v["device_benchmarks"].as_array() {
        Some(devices) if devices.is_empty() => Ok(()),
        _ => Err(format!(
            "device_benchmarks should be an empty array, got {}",
            v["device_benchmarks"]
        )),
    }
}

#[rstest]
#[case::help(Case {
    expect: Expect {
        code: Some(0),
        stdout_contains: vec!["HemiProve"],
        ..Default::default()
    },
    ..Case::new("help", &["--help"])
})]
#[case::unknown_subcommand(Case {
    expect: Expect {
        code: Some(2),
        stderr_contains: vec!["unrecognized subcommand"],
        ..Default::default()
    },
    ..Case::new("unknown_subcommand", &["bogus"])
})]
#[case::init_refuses_existing_config(Case {
    expect: Expect {
        code: Some(0),
        stdout_contains: vec!["already exists", "--force"],
        ..Default::default()
    },
    ..Case::new("init_refuses_existing_config", &["init"])
})]
#[case::init_force_writes_sandbox_config(Case {
    setup: |sb| std::fs::remove_file(sb.config_path()).unwrap(),
    expect: Expect {
        code: Some(0),
        files_exist: vec!["home/.zkminer/config.toml"],
        ..Default::default()
    },
    ..Case::new("init_force_writes_sandbox_config", &["init", "--force"])
})]
#[case::benchmark_json_no_workers(Case {
    expect: Expect {
        code: Some(0),
        json: Some(benchmark_json_without_devices),
        // A plain benchmark (no --calibrate) writes no state.
        files_absent: vec!["home/.zkminer/benchmarks.json"],
        ..Default::default()
    },
    ..Case::new("benchmark_json_no_workers", &["benchmark", "--json"])
})]
fn smoke(#[case] case: Case) {
    run_case(case);
}

#[test]
fn failing_case_reports_name_and_output() {
    let case = Case {
        expect: Expect {
            code: Some(1),
            ..Default::default()
        },
        ..Case::new("deliberately_wrong", &["--help"])
    };
    let err = catch_unwind(AssertUnwindSafe(|| run_case(case)))
        .expect_err("a case with a wrong expectation must fail");
    let msg = err
        .downcast_ref::<String>()
        .cloned()
        .unwrap_or_default();

    for want in [
        "e2e case `deliberately_wrong` failed",
        "exit code: want 1",
        "command: zkminer --help",
        "--- stdout ---",
        "HemiProve",
        "--- stderr ---",
    ] {
        assert!(msg.contains(want), "report missing {want:?}:\n{msg}");
    }
}

#[test]
fn sandbox_layout() {
    let sb = Sandbox::new();
    assert!(sb.zkminer().is_file());
    assert!(sb.zkminer().starts_with(sb.root()));

    let config = std::fs::read_to_string(sb.config_path()).unwrap();
    let provers = sb.provers_dir().display().to_string();
    assert!(
        config.contains("worker_search_paths") && config.contains(&provers),
        "config should list {provers} in worker_search_paths:\n{config}"
    );

    let shims = sb.shims_dir().display().to_string();
    assert!(sb.path_env().starts_with(&format!("{shims}:")));

    let cmd = sb.command();
    let env: Vec<_> = cmd.get_envs().collect();
    let home = sb.home();
    assert!(env.contains(&(std::ffi::OsStr::new("HOME"), Some(home.as_os_str()))));
}
