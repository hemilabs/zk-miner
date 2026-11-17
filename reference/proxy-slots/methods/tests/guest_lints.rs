//! The guest lints of plan §21.1 item 4: nothing the prover's host controls may reach the guest's
//! journal or a selection, so the guest may not use a default-seeded `HashMap`/`HashSet`
//! (`sys_rand`), `env::exit`, the environment or arguments, the cycle count, or `sys_rand` itself.
//!
//! Two checks here, each shown to catch every violation of the lint control guest, which commits
//! all of them:
//!
//! 1. **The built ELF's call graph** (`llvm-objdump`): `sys_rand` is called only by risc0's
//!    `env::init` (the memory-image entropy every risc0 guest draws, which never reaches the
//!    journal), and nothing calls `sys_getenv`, `sys_argv`, `sys_argc`, `sys_cycle_count`,
//!    `env::exit` or `env::pause`, nor links the standard library's hash-map seed. This covers every
//!    crate the guest links, through the platform's syscall functions.
//! 2. **The sources** of everything the guest links from this repository (the guest, the
//!    statement, the prelude): no banned name outside comments, strings and test modules. This
//!    covers what the ELF cannot show, an early `env::exit(0)`, which halts like a return from
//!    `main`.
//!
//! The third, clippy with `guest/clippy.toml`, is `../check-guest-lints.sh` (it needs the risc0
//! toolchain's clippy and its own target dir).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use hemiprove_proxy_slots_methods::{LINT_CONTROL_ELF, PROXY_SLOTS_ELF};

/// Syscall wrappers no guest code may call.
const BANNED_CALLEES: &[&str] = &[
    "sys_getenv",
    "sys_argv",
    "sys_argc",
    "sys_cycle_count",
    "risc0_zkvm::guest::env::exit",
    "risc0_zkvm::guest::env::pause",
    "risc0_zkvm::guest::env::cycle_count",
];
/// `sys_rand`'s only allowed caller.
const SYS_RAND_CALLER: &str = "risc0_zkvm::guest::env::init";
/// Symbols whose presence means a default-seeded hash map is linked.
const BANNED_SYMBOLS: &[&str] = &["hashmap_random_keys", "RandomState"];

fn objdump() -> PathBuf {
    let risc0 = dirs_home().join(".risc0/toolchains");
    let bundled = std::fs::read_dir(&risc0).ok().into_iter().flatten().flatten().map(|e| {
        e.path().join("lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-objdump")
    });
    for candidate in bundled.chain([PathBuf::from("/usr/bin/llvm-objdump")]) {
        if candidate.is_file() {
            return candidate;
        }
    }
    panic!("no llvm-objdump: install LLVM, or the risc0 toolchain with rzup");
}

fn dirs_home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").expect("HOME"))
}

/// The user ELF inside risc0's program binary (`*_ELF` is kernel + user).
fn user_elf(program: &[u8]) -> Vec<u8> {
    risc0_binfmt::ProgramBinary::decode(program).expect("a risc0 program binary").user_elf.to_vec()
}

/// What the ELF breaks: `(caller, callee)` for banned calls, and banned symbols present.
fn elf_violations(program: &[u8]) -> BTreeSet<String> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("guest.elf");
    std::fs::write(&path, user_elf(program)).unwrap();
    let out = Command::new(objdump()).args(["-d", "-C", "--no-show-raw-insn"]).arg(&path).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8(out.stdout).unwrap();
    let mut violations = BTreeSet::new();
    let mut function = String::new();
    let mut symbols = BTreeSet::new();
    for line in text.lines() {
        // `0020b1a0 <risc0_zkvm::guest::env::init>:` starts a function.
        if let Some(name) = line.strip_suffix(">:").and_then(|l| l.split_once(" <")).map(|(_, n)| n) {
            function = name.to_string();
            symbols.insert(function.clone());
            continue;
        }
        // An instruction whose target is a whole symbol: `jalr 0x3c0(ra) <sys_getenv>`.
        let Some(target) = line.trim_end().strip_suffix('>').and_then(|l| l.rsplit_once('<')).map(|(_, t)| t) else {
            continue;
        };
        if BANNED_CALLEES.contains(&target) {
            violations.insert(format!("{function} calls {target}"));
        }
        if target == "sys_rand" && function != SYS_RAND_CALLER {
            violations.insert(format!("{function} calls sys_rand"));
        }
    }
    for s in &symbols {
        if BANNED_SYMBOLS.iter().any(|b| s.contains(b)) {
            violations.insert(format!("links {s}"));
        }
    }
    assert!(symbols.contains(SYS_RAND_CALLER), "the disassembly has no symbols to check");
    violations
}

#[test]
fn the_guest_elf_reaches_no_host_input() {
    let v = elf_violations(PROXY_SLOTS_ELF);
    assert!(v.is_empty(), "{v:#?}");
}

#[test]
fn the_elf_check_catches_every_violation_of_the_control() {
    let v = elf_violations(LINT_CONTROL_ELF);
    let text = v.iter().cloned().collect::<Vec<_>>().join("\n");
    for expected in ["calls sys_getenv", "calls sys_argv", "calls sys_argc", "calls sys_cycle_count", "main calls risc0_zkvm::guest::env::exit", "hashmap_random_keys calls sys_rand", "links "] {
        assert!(text.contains(expected), "{expected:?} not found in:\n{text}");
    }
}

// ---------------------------------------------------------------------------------------------
// Sources.

/// Names no guest source may use, outside comments, strings and test modules.
const BANNED_NAMES: &[&str] = &[
    "HashMap",
    "HashSet",
    "RandomState",
    "getrandom",
    "sys_rand",
    "thread_rng",
    "cycle_count",
    "env::exit",
    "env::pause",
    "process::exit",
    "env::var",
    "env::args",
    "std::env",
    "sys_getenv",
    "sys_argv",
    "sys_argc",
];

/// `src` without comments, string and char literals, and from the first `#[cfg(test)]` module on
/// (this repository keeps tests last in each file).
fn code_only(src: &str) -> String {
    let src = match src.find("#[cfg(test)]\nmod tests") {
        Some(i) => &src[..i],
        None => src,
    };
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < b.len() {
        match (b[i], b.get(i + 1)) {
            (b'/', Some(b'/')) => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            (b'/', Some(b'*')) => {
                let mut depth = 0;
                while i < b.len() {
                    if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                        depth += 1;
                        i += 2;
                    } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                        depth -= 1;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
                out.push(' ');
            }
            (b'r', Some(b'"' | b'#')) if i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_') => {
                // A raw string: r"…", r#"…"#, …
                let mut j = i + 1;
                let mut hashes = 0;
                while b.get(j) == Some(&b'#') {
                    hashes += 1;
                    j += 1;
                }
                if b.get(j) != Some(&b'"') {
                    out.push('r');
                    i += 1;
                    continue;
                }
                let close: Vec<u8> = std::iter::once(b'"').chain(std::iter::repeat_n(b'#', hashes)).collect();
                j += 1;
                while j < b.len() && !b[j..].starts_with(&close) {
                    j += 1;
                }
                i = j + close.len();
                out.push_str("\"\"");
            }
            (b'"', _) => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
                i += 1;
                out.push_str("\"\"");
            }
            (b'\'', _) if b.get(i + 2) == Some(&b'\'') || (b.get(i + 1) == Some(&b'\\') && b.get(i + 3) == Some(&b'\'')) => {
                // A char literal ('x', '\n'); a lifetime has no closing quote nearby.
                i += if b[i + 1] == b'\\' { 4 } else { 3 };
                out.push_str("' '");
            }
            (c, _) => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    out
}

fn is_ident(c: Option<char>) -> bool {
    c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The banned names `src` uses, each as a whole identifier path.
fn banned_names(src: &str) -> BTreeSet<&'static str> {
    let code = code_only(src);
    let mut found = BTreeSet::new();
    for name in BANNED_NAMES {
        let mut from = 0;
        while let Some(at) = code[from..].find(name) {
            let start = from + at;
            let end = start + name.len();
            if !is_ident(code[..start].chars().next_back()) && !is_ident(code[end..].chars().next()) {
                found.insert(*name);
            }
            from = end;
        }
    }
    found
}

fn sources(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(sources(&p));
        } else if p.extension().is_some_and(|x| x == "rs") && p.file_name().is_some_and(|n| n != "tests.rs") {
            out.push(p);
        }
    }
    out.sort();
    out
}

fn reference_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

#[test]
fn the_guest_sources_use_no_banned_name() {
    let mut violations = BTreeMap::new();
    let dirs = ["proxy-slots/guest/src", "proxy-slots/statement/src", "eth-prelude/src"];
    let mut files = 0;
    for d in dirs {
        for f in sources(&reference_dir().join(d)) {
            files += 1;
            let found = banned_names(&std::fs::read_to_string(&f).unwrap());
            if !found.is_empty() {
                violations.insert(f.display().to_string(), found);
            }
        }
    }
    assert!(files >= 12, "only {files} source files found");
    assert!(violations.is_empty(), "{violations:#?}");
}

#[test]
fn the_source_scan_catches_the_control_and_ignores_comments() {
    let control = std::fs::read_to_string(reference_dir().join("proxy-slots/lint-control/src/main.rs")).unwrap();
    let found = banned_names(&control);
    for expected in ["HashMap", "cycle_count", "env::var", "env::args", "env::exit"] {
        assert!(found.contains(expected), "{expected} not found: {found:?}");
    }
    let quiet = "// HashMap\n/* env::exit /* nested sys_rand */ */\nlet s = \"std::env\"; let r = r#\"cycle_count\"#;\n\
                 let c = '\"'; fn f<'a>(x: &'a u8) {}\nstruct MyHashMapLike; fn my_cycle_count_x() {}\n";
    assert_eq!(banned_names(quiet), BTreeSet::new());
    assert_eq!(banned_names("fn main() { risc0_zkvm::guest::env::exit(0) }"), BTreeSet::from(["env::exit"]));
    assert_eq!(banned_names("x\n#[cfg(test)]\nmod tests { use std::collections::HashMap; }"), BTreeSet::new());
}
