//! The guest lints of plan §21.1 item 4: nothing the prover's host controls may reach the guest's
//! journal or a selection, so the guest may not use a default-seeded `HashMap`/`HashSet`
//! (`sys_rand`), `env::exit`, the environment or arguments, the cycle count, `sys_rand` itself, the
//! raw keccak permutation's status, another file descriptor than stdin, or any syscall but through
//! the platform's own wrappers.
//!
//! Two checks here, each shown to catch every violation of the lint control guest, which commits
//! all of them (including the ways around the names: the raw `syscall_*_nr` entry points, fd 3,
//! `FdReader`, a `static` read by a function that captures nothing):
//!
//! 1. **The built ELF** (`llvm-objdump`), which covers every crate the guest links:
//!    - an `ecall` only inside the platform's syscall wrappers (`sys_*`, `syscall_*`) and risc0's
//!      keccak batcher, and the raw `syscall_*` entry points called only by those wrappers;
//!    - no call to `sys_getenv`, `sys_argv`, `sys_argc`, `sys_cycle_count`, `env::exit`,
//!      `env::pause` or `env::cycle_count`; `sys_rand` called only by risc0's `env::init` (the
//!      memory-image entropy every risc0 guest draws, which never reaches the journal); `sys_keccak`
//!      only by the batcher, which keeps its status to itself;
//!    - the syscall name strings (`risc0_zkvm_platform::syscall::nr::SYS_*`, which every syscall
//!      passes) referenced only by their wrappers: `SYS_GETENV`, `SYS_ARGV`, `SYS_ARGC` and
//!      `SYS_CYCLE_COUNT` by nothing, `SYS_RANDOM` by `sys_rand` alone;
//!    - no standard hash-map seed linked.
//! 2. **The sources** of everything the guest links from this repository (the guest, the
//!    statement, the prelude): no banned name outside comments, strings and test modules, among
//!    them `syscall_*`, `SYS_*`, `asm!`, `send_recv`, `FdReader`, `sys_keccak`, a `sys_read` of any
//!    fd but `fileno::STDIN`, and `static`, `thread_local`, `Cell`, `RefCell` (a function the guards
//!    accept as a derivation captures nothing, but could read one of those). This covers what the
//!    ELF cannot show: an early `env::exit(0)`, which halts like a return from `main`, and the fd a
//!    read names.
//!
//! The third, clippy with `guest/clippy.toml`, is `../check-guest-lints.sh` (it needs the risc0
//! toolchain's clippy and its own target dir).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use hemiprove_proxy_slots_methods::{LINT_CONTROL_ELF, PROXY_SLOTS_ELF};

/// Syscall wrappers and runtime functions no guest code may call.
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
/// risc0's keccak batcher: `sys_keccak`'s only callers (the permutation's status stays inside), and
/// the only code besides the wrappers that may hold its inlined `ecall`.
const KECCAK_BATCHER: &[&str] = &["<risc0_zkvm::guest::env::batcher::KeccakBatcher>::update", "risc0_keccak_update"];
/// Symbols whose presence means a default-seeded hash map is linked.
const BANNED_SYMBOLS: &[&str] = &["hashmap_random_keys", "RandomState"];
/// The prefix of every syscall name string (`risc0_zkvm_platform::syscall::nr`).
const SYSCALL_NAME_PREFIX: &str = "risc0_zkvm_platform::syscall::nr::";
/// Syscall names nothing may reference, and those only some functions may.
const UNREFERENCED_NAMES: &[&str] = &["SYS_GETENV", "SYS_ARGV", "SYS_ARGC", "SYS_CYCLE_COUNT"];
const NAME_OWNERS: &[(&str, &[&str])] = &[
    ("SYS_RANDOM", &["sys_rand"]),
    (
        "SYS_KECCAK",
        &[
            "sys_keccak",
            "sys_prove_keccak",
            "<risc0_zkvm::guest::env::batcher::KeccakBatcher>::update",
            "risc0_keccak_update",
        ],
    ),
];

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

/// A platform function's plain name (`sys_read`, `syscall_0_nr`), whether or not its symbol carries
/// the module path.
fn platform_name(f: &str) -> &str {
    f.strip_prefix("risc0_zkvm_platform::syscall::").unwrap_or(f)
}

/// The platform's syscall wrappers and raw entry points: where an `ecall` belongs.
fn is_wrapper(f: &str) -> bool {
    let f = platform_name(f);
    f.starts_with("sys_") || f.starts_with("syscall_")
}

/// The `.rodata` addresses of the syscall name strings in `elf` (a 32-bit little-endian ELF):
/// `address → SYS_…`.
fn syscall_names(elf: &[u8]) -> BTreeMap<u32, String> {
    let u16_at = |o: usize| u16::from_le_bytes(elf[o..o + 2].try_into().unwrap()) as usize;
    let u32_at = |o: usize| u32::from_le_bytes(elf[o..o + 4].try_into().unwrap());
    let (shoff, shentsize, shnum, shstrndx) = (u32_at(0x20) as usize, u16_at(0x2e), u16_at(0x30), u16_at(0x32));
    let section = |i: usize| {
        let h = shoff + i * shentsize;
        (u32_at(h) as usize, u32_at(h + 12), u32_at(h + 16) as usize, u32_at(h + 20) as usize)
    };
    let strtab = section(shstrndx).2;
    let mut out = BTreeMap::new();
    for i in 0..shnum {
        let (name, addr, offset, size) = section(i);
        if !elf[strtab + name..].starts_with(b".rodata\0") {
            continue;
        }
        let data = &elf[offset..offset + size];
        let prefix = SYSCALL_NAME_PREFIX.as_bytes();
        let mut at = 0;
        while let Some(p) = data[at..].windows(prefix.len()).position(|w| w == prefix) {
            let start = at + p;
            let end = start + data[start..].iter().position(|&b| b == 0).unwrap_or(data.len() - start);
            let full = String::from_utf8_lossy(&data[start..end]).into_owned();
            out.insert(addr + start as u32, full[SYSCALL_NAME_PREFIX.len()..].to_string());
            at = end;
        }
    }
    out
}

/// What the ELF breaks: banned calls and callers, `ecall`s and syscall name strings outside the
/// wrappers, and banned symbols present.
fn elf_violations(program: &[u8]) -> BTreeSet<String> {
    let user = user_elf(program);
    let names = syscall_names(&user);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("guest.elf");
    std::fs::write(&path, &user).unwrap();
    let out = Command::new(objdump()).args(["-d", "-C", "--no-show-raw-insn"]).arg(&path).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8(out.stdout).unwrap();
    let mut violations = BTreeSet::new();
    let mut function = String::new();
    let mut symbols = BTreeSet::new();
    // Registers holding an address `auipc`/`lui` (and `addi`) built: how code names a string.
    let mut regs: BTreeMap<String, u32> = BTreeMap::new();
    for line in text.lines() {
        // `0020b1a0 <risc0_zkvm::guest::env::init>:` starts a function.
        if let Some(name) = line.strip_suffix(">:").and_then(|l| l.split_once(" <")).map(|(_, n)| n) {
            function = name.to_string();
            symbols.insert(function.clone());
            regs.clear();
            continue;
        }
        // `  200950:      auipc   a0, 0x14` (target comments after `<` dropped).
        let Some((pc, insn)) = line.trim_start().split_once(':') else { continue };
        let Ok(pc) = u32::from_str_radix(pc.trim(), 16) else { continue };
        let insn = insn.split('<').next().unwrap_or("").trim();
        let (op, args) = insn.split_once(char::is_whitespace).map_or((insn, ""), |(o, a)| (o, a.trim()));
        let args: Vec<&str> = args.split(',').map(str::trim).collect();
        let imm = |s: &str| -> Option<i64> {
            let (neg, s) = s.strip_prefix('-').map_or((false, s), |r| (true, r));
            let v = match s.strip_prefix("0x") {
                Some(h) => i64::from_str_radix(h, 16).ok()?,
                None => s.parse().ok()?,
            };
            Some(if neg { -v } else { v })
        };
        match op {
            "ecall" if !is_wrapper(&function) && !KECCAK_BATCHER.contains(&function.as_str()) => {
                violations.insert(format!("{function} holds an ecall"));
            }
            "auipc" if args.len() == 2 => {
                if let Some(i) = imm(args[1]) {
                    regs.insert(args[0].to_string(), pc.wrapping_add((i << 12) as u32));
                }
            }
            "lui" if args.len() == 2 => {
                if let Some(i) = imm(args[1]) {
                    regs.insert(args[0].to_string(), (i << 12) as u32);
                }
            }
            "addi" if args.len() == 3 && regs.contains_key(args[1]) => {
                let v = regs[args[1]].wrapping_add(imm(args[2]).unwrap_or(0) as u32);
                if let Some(name) = names.get(&v) {
                    let owners = NAME_OWNERS.iter().find(|(n, _)| n == name).map(|(_, o)| *o);
                    let allowed = if UNREFERENCED_NAMES.contains(&name.as_str()) {
                        false
                    } else if let Some(owners) = owners {
                        owners.contains(&platform_name(&function))
                    } else {
                        is_wrapper(&function)
                    };
                    if !allowed {
                        violations.insert(format!("{function} references {name}"));
                    }
                }
                regs.insert(args[0].to_string(), v);
            }
            _ => {
                // Anything else that writes its first operand ends what that register held.
                if let Some(rd) = args.first() {
                    regs.remove(*rd);
                }
            }
        }
        // An instruction whose target is a whole symbol: `jalr 0x3c0(ra) <sys_getenv>`.
        let Some(target) = line.trim_end().strip_suffix('>').and_then(|l| l.rsplit_once('<')).map(|(_, t)| t) else {
            continue;
        };
        let callee = platform_name(target);
        if BANNED_CALLEES.contains(&callee) || BANNED_CALLEES.contains(&target) {
            violations.insert(format!("{function} calls {target}"));
        }
        if callee == "sys_rand" && function != SYS_RAND_CALLER {
            violations.insert(format!("{function} calls sys_rand"));
        }
        if callee == "sys_keccak" && !KECCAK_BATCHER.contains(&function.as_str()) {
            violations.insert(format!("{function} calls sys_keccak"));
        }
        if callee.starts_with("syscall_") && !is_wrapper(&function) {
            violations.insert(format!("{function} calls {target}"));
        }
    }
    for s in &symbols {
        if BANNED_SYMBOLS.iter().any(|b| s.contains(b)) {
            violations.insert(format!("links {s}"));
        }
    }
    assert!(symbols.contains(SYS_RAND_CALLER), "the disassembly has no symbols to check");
    assert!(names.values().any(|n| n == "SYS_RANDOM"), "no syscall name strings found: {names:?}");
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
    for expected in [
        "calls sys_getenv",
        "calls sys_argv",
        "calls sys_argc",
        "calls sys_cycle_count",
        "main calls risc0_zkvm::guest::env::exit",
        "hashmap_random_keys calls sys_rand",
        "links ",
        // The raw entry points, past the wrappers' names: whether inlined (an ecall, the name
        // string) or not (a call to syscall_*), each is caught.
        "references SYS_RANDOM",
        "references SYS_CYCLE_COUNT",
        "references SYS_GETENV",
        "calls sys_keccak",
    ] {
        assert!(text.contains(expected), "{expected:?} not found in:\n{text}");
    }
    assert!(
        v.iter().any(|x| x.ends_with("holds an ecall") || x.contains("calls syscall_")),
        "a raw syscall outside the wrappers not reported:\n{text}"
    );
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
    "sys_keccak",
    "send_recv",
    "FdReader",
    "asm",
    "global_asm",
    "static",
    "thread_local",
    "Cell",
    "RefCell",
    "UnsafeCell",
];
/// Identifier prefixes no guest source may use: the raw syscall entry points and the syscall names.
const BANNED_PREFIXES: &[&str] = &["syscall_", "SYS_"];
/// A read of this fd only (`sys_read(fileno::STDIN, …)`): any other fd is a channel the prover's host
/// fills.
const STDIN: &str = "fileno::STDIN";

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

/// The banned names `src` uses, each as a whole identifier path (`static` but not the lifetime
/// `'static`), the banned prefixes as `syscall_…`/`SYS_…`, and a `sys_read` of an fd other than
/// stdin as `sys_read(fd)`.
fn banned_names(src: &str) -> BTreeSet<String> {
    let code = code_only(src);
    let mut found = BTreeSet::new();
    let before = |start: usize| code[..start].chars().next_back();
    for name in BANNED_NAMES {
        let mut from = 0;
        while let Some(at) = code[from..].find(name) {
            let start = from + at;
            let end = start + name.len();
            if !is_ident(before(start)) && before(start) != Some('\'') && !is_ident(code[end..].chars().next()) {
                found.insert(name.to_string());
            }
            from = end;
        }
    }
    for prefix in BANNED_PREFIXES {
        let mut from = 0;
        while let Some(at) = code[from..].find(prefix) {
            let start = from + at;
            if !is_ident(before(start)) {
                found.insert(format!("{prefix}…"));
            }
            from = start + prefix.len();
        }
    }
    for read in ["sys_read(", "sys_read_words("] {
        let mut from = 0;
        while let Some(at) = code[from..].find(read) {
            let start = from + at;
            let end = start + read.len();
            let fd = code[end..].split(',').next().unwrap_or("").trim();
            if !is_ident(before(start)) && fd != STDIN && !fd.ends_with(&format!("::{STDIN}")) {
                found.insert("sys_read(fd)".to_string());
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
    for expected in [
        "HashMap",
        "cycle_count",
        "env::var",
        "env::args",
        "env::exit",
        "syscall_…",
        "SYS_…",
        "sys_read(fd)",
        "sys_keccak",
        "FdReader",
        "static",
        "Cell",
    ] {
        assert!(found.contains(expected), "{expected} not found: {found:?}");
    }
    let quiet = "// HashMap\n/* env::exit /* nested sys_rand */ */\nlet s = \"std::env\"; let r = r#\"cycle_count\"#;\n\
                 let c = '\"'; fn f<'a>(x: &'a u8) {}\nstruct MyHashMapLike; fn my_cycle_count_x() {}\n\
                 fn w() -> Witness<'static> {} struct OnceCellLike; fn my_syscall_x() {} fn MY_SYS_X() {}\n\
                 let n = unsafe { sys_read(fileno::STDIN, p, 4) };\n";
    assert_eq!(banned_names(quiet), BTreeSet::new());
    let one = |s: &str| banned_names(s).into_iter().collect::<Vec<_>>();
    assert_eq!(one("fn main() { risc0_zkvm::guest::env::exit(0) }"), ["env::exit"]);
    assert_eq!(one("x\n#[cfg(test)]\nmod tests { use std::collections::HashMap; }"), Vec::<String>::new());
    // The ways around the names a reviewer found, and the guard escapes the types cannot stop.
    assert_eq!(one("unsafe { syscall_0_nr(11, nr::SYS_RANDOM, p, 8) }"), ["SYS_…", "syscall_…"]);
    assert_eq!(one("let n = unsafe { sys_read(3, p, 16) };"), ["sys_read(fd)"]);
    assert_eq!(one("unsafe { core::arch::asm!(\"ecall\") }"), ["asm"]);
    assert_eq!(one("static HINT: AtomicU64 = AtomicU64::new(0);"), ["static"]);
    assert_eq!(one("thread_local! { static X: u8 = 0 }"), ["static", "thread_local"]);
    assert_eq!(one("let c = std::cell::RefCell::new(0);"), ["RefCell"]);
    assert_eq!(one("let r = env::FdReader::new(3);"), ["FdReader"]);
    assert_eq!(one("let a = hdr.derive(|_| SMUGGLED.load(Ordering::Relaxed)); static SMUGGLED: u8 = 0;"), ["static"]);
}
