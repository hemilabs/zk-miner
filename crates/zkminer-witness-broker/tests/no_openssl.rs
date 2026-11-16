//! The broker links no OpenSSL (review r2 e2e): inside its sandbox OpenSSL cannot read a CA store,
//! so a broker built with it fails every TLS endpoint and disables witness serving. Its TLS is
//! rustls with the compiled-in webpki roots.
//!
//! Two checks, because cargo unifies features per invocation: the broker binary this test run
//! built has no `libssl`/`libcrypto` in its `DT_NEEDED`; and in the workspace as a whole — what
//! `cargo build --release` of the workspace, or of `zkminer-cli` with the broker, resolves — no
//! normal dependency path from the broker or the miner reaches `openssl-sys` or `native-tls`, and
//! reqwest's TLS is never native.

use std::collections::{HashMap, HashSet, VecDeque};

const BROKER: &str = env!("CARGO_BIN_EXE_zkminer-witness-broker");

fn u16_at(b: &[u8], o: usize) -> usize {
    u16::from_le_bytes([b[o], b[o + 1]]) as usize
}
fn u32_at(b: &[u8], o: usize) -> usize {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) as usize
}
fn u64_at(b: &[u8], o: usize) -> usize {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) as usize
}

/// The `DT_NEEDED` entries of a little-endian ELF64 file.
fn needed(path: &str) -> Vec<String> {
    let b = std::fs::read(path).unwrap();
    assert_eq!(&b[..4], b"\x7fELF");
    assert_eq!((b[4], b[5]), (2, 1), "ELF64 little-endian");
    let (shoff, shentsize, shnum) = (u64_at(&b, 0x28), u16_at(&b, 0x3a), u16_at(&b, 0x3c));
    let section = |i: usize| shoff + i * shentsize;
    let mut out = Vec::new();
    for i in 0..shnum {
        let s = section(i);
        if u32_at(&b, s + 4) != 6 {
            continue; // SHT_DYNAMIC
        }
        let (off, size, link) = (u64_at(&b, s + 0x18), u64_at(&b, s + 0x20), u32_at(&b, s + 0x28));
        let strtab = u64_at(&b, section(link) + 0x18);
        for e in (off..off + size).step_by(16) {
            let (tag, val) = (u64_at(&b, e), u64_at(&b, e + 8));
            if tag == 1 {
                let start = strtab + val;
                let end = start + b[start..].iter().position(|&c| c == 0).unwrap();
                out.push(String::from_utf8_lossy(&b[start..end]).into_owned());
            }
        }
    }
    out
}

#[test]
fn the_broker_binary_links_no_openssl() {
    let libs = needed(BROKER);
    assert!(libs.iter().any(|l| l.starts_with("libc.so")), "the parser found the dynamic section: {libs:?}");
    for l in &libs {
        assert!(!l.starts_with("libssl") && !l.starts_with("libcrypto"), "the broker links {l}: {libs:?}");
    }
}

#[test]
fn no_workspace_build_gives_the_broker_or_the_miner_openssl() {
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml");
    let cargo = option_env!("CARGO").unwrap_or("cargo");
    let platform = format!("{}-unknown-linux-gnu", std::env::consts::ARCH);
    let out = std::process::Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--locked", "--offline", "--filter-platform", &platform, "--manifest-path", manifest])
        .output()
        .expect("cargo metadata");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let m: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let names: HashMap<&str, &str> =
        m["packages"].as_array().unwrap().iter().map(|p| (p["id"].as_str().unwrap(), p["name"].as_str().unwrap())).collect();
    let nodes: HashMap<&str, &serde_json::Value> =
        m["resolve"]["nodes"].as_array().unwrap().iter().map(|n| (n["id"].as_str().unwrap(), n)).collect();
    // Normal (non-dev, non-build) dependencies only: what links into the binaries.
    let normal_deps = |id: &str| -> Vec<&str> {
        nodes[id]["deps"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|d| d["dep_kinds"].as_array().unwrap().iter().any(|k| k["kind"].is_null()))
            .map(|d| d["pkg"].as_str().unwrap())
            .collect()
    };
    for root in ["zkminer-witness-broker", "zkminer-cli"] {
        let start = names.iter().find(|(_, n)| **n == root).map(|(id, _)| *id).expect(root);
        let mut seen = HashSet::from([start]);
        let mut queue = VecDeque::from([(start, vec![root])]);
        while let Some((id, path)) = queue.pop_front() {
            let name = names[id];
            assert!(
                !["openssl-sys", "openssl", "native-tls", "hyper-tls", "tokio-native-tls"].contains(&name),
                "{root} reaches {name}: {}",
                path.join(" -> ")
            );
            for dep in normal_deps(id) {
                if seen.insert(dep) {
                    let mut p = path.clone();
                    p.push(names[dep]);
                    queue.push_back((dep, p));
                }
            }
        }
    }
    for (id, n) in &nodes {
        if names[id] == "reqwest" {
            let features: Vec<&str> = n["features"].as_array().unwrap().iter().map(|f| f.as_str().unwrap()).collect();
            for f in ["default-tls", "native-tls", "native-tls-crate", "__native-tls"] {
                assert!(!features.contains(&f), "reqwest is built with {f} in this workspace: {features:?}");
            }
            assert!(features.contains(&"rustls-tls-webpki-roots"), "{features:?}");
        }
    }
}
