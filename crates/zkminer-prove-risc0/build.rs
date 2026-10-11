fn main() {
    println!("cargo:rerun-if-env-changed=ZKMINER_RISC0_GUESTS_DIR");
    // Embed guests built elsewhere: rzup, which compiles them, does not run on Windows.
    if let Some(dir) = std::env::var_os("ZKMINER_RISC0_GUESTS_DIR") {
        import_prebuilt_guests(std::path::Path::new(&dir));
        return;
    }

    // Skip guest compilation when RISC0_SKIP_BUILD is set (for CI/fast dev builds).
    if std::env::var("RISC0_SKIP_BUILD").is_ok() {
        // Generate empty stubs so the binary still compiles.
        let out_dir = std::env::var("OUT_DIR").unwrap();
        let methods_path = std::path::Path::new(&out_dir).join("methods.rs");
        std::fs::write(
            &methods_path,
            r#"
pub const FIBONACCI_ELF: &[u8] = &[];
pub const FIBONACCI_ID: [u32; 8] = [0u32; 8];
pub const SHA256_CHAIN_ELF: &[u8] = &[];
pub const SHA256_CHAIN_ID: [u32; 8] = [0u32; 8];
pub const ECDSA_VERIFY_ELF: &[u8] = &[];
pub const ECDSA_VERIFY_ID: [u32; 8] = [0u32; 8];
pub const BIGINT_MUL_ELF: &[u8] = &[];
pub const BIGINT_MUL_ID: [u32; 8] = [0u32; 8];
pub const MEMORY_MERKLE_ELF: &[u8] = &[];
pub const MEMORY_MERKLE_ID: [u32; 8] = [0u32; 8];
pub const CHACHA_MIX_ELF: &[u8] = &[];
pub const CHACHA_MIX_ID: [u32; 8] = [0u32; 8];
pub const RV32IM_TORTURE_ELF: &[u8] = &[];
pub const RV32IM_TORTURE_ID: [u32; 8] = [0u32; 8];
pub const EDGE_CASE_ARITH_ELF: &[u8] = &[];
pub const EDGE_CASE_ARITH_ID: [u32; 8] = [0u32; 8];
pub const MEMORY_STRESS_ELF: &[u8] = &[];
pub const MEMORY_STRESS_ID: [u32; 8] = [0u32; 8];
pub const PRECOMPILE_INTERLEAVE_ELF: &[u8] = &[];
pub const PRECOMPILE_INTERLEAVE_ID: [u32; 8] = [0u32; 8];
pub const SEGMENT_BOUNDARY_ELF: &[u8] = &[];
pub const SEGMENT_BOUNDARY_ID: [u32; 8] = [0u32; 8];
pub const BABYBEAR_STRESS_ELF: &[u8] = &[];
pub const BABYBEAR_STRESS_ID: [u32; 8] = [0u32; 8];
pub const MINIMAL_PROOF_ELF: &[u8] = &[];
pub const MINIMAL_PROOF_ID: [u32; 8] = [0u32; 8];
"#,
        )
        .expect("failed to write method stubs");
        return;
    }

    let guest_dir =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../zkminer-prover/guests/risc0");

    let mut guests = std::collections::HashMap::new();
    let opts = risc0_build::GuestOptions::default();
    guests.insert("fibonacci", opts.clone());
    guests.insert("sha256-chain", opts.clone());
    guests.insert("ecdsa-verify", opts.clone());
    guests.insert("bigint-mul", opts.clone());
    guests.insert("memory-merkle", opts.clone());
    guests.insert("chacha-mix", opts.clone());
    guests.insert("rv32im-torture", opts.clone());
    guests.insert("edge-case-arith", opts.clone());
    guests.insert("memory-stress", opts.clone());
    guests.insert("precompile-interleave", opts.clone());
    guests.insert("segment-boundary", opts.clone());
    guests.insert("babybear-stress", opts.clone());
    guests.insert("minimal-proof", opts);
    risc0_build::embed_methods_with_options(guests);
    // Tell cargo to watch the guest source directories.
    println!(
        "cargo:rerun-if-changed={}",
        guest_dir.join("fibonacci/src/main.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        guest_dir.join("sha256-chain/src/main.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        guest_dir.join("ecdsa-verify/src/main.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        guest_dir.join("bigint-mul/src/main.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        guest_dir.join("memory-merkle/src/main.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        guest_dir.join("chacha-mix/src/main.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        guest_dir.join("rv32im-torture/src/main.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        guest_dir.join("edge-case-arith/src/main.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        guest_dir.join("memory-stress/src/main.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        guest_dir
            .join("precompile-interleave/src/main.rs")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        guest_dir.join("segment-boundary/src/main.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        guest_dir.join("babybear-stress/src/main.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        guest_dir.join("minimal-proof/src/main.rs").display()
    );
}

/// Embed guests from `dir`: the `methods.rs` a real build of this crate generated
/// (with `risc0_build`) and the guest binaries it names, all copied into `dir`.
///
/// `methods.rs` names each binary by an absolute path on the machine that built it;
/// those are repointed at the file of the same name in `dir`. The image IDs are kept
/// as generated, so they always match the binaries they were computed from.
fn import_prebuilt_guests(dir: &std::path::Path) {
    let methods_src = dir.join("methods.rs");
    println!("cargo:rerun-if-changed={}", methods_src.display());
    let methods = std::fs::read_to_string(&methods_src).unwrap_or_else(|e| {
        panic!(
            "ZKMINER_RISC0_GUESTS_DIR: reading {}: {e}",
            methods_src.display()
        )
    });

    let mut out = String::new();
    let mut guests = 0;
    for line in methods.lines() {
        // Generated lines are `pub const X_ELF: &[u8] = include_bytes!("<path>");` and
        // `pub const X_PATH: &str = "<path>";`, with the path as a Rust string literal.
        let is_elf = line.contains("include_bytes!(\"");
        let is_path = line.contains("_PATH: &str = \"");
        if !(is_elf || is_path) {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        let start = line.find('"').unwrap() + 1;
        let end = line.rfind('"').unwrap();
        // Unescape the literal's backslashes; a Windows build of it would double them.
        let original = line[start..end].replace("\\\\", "\\");
        let name = original
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or_else(|| panic!("no file name in {original:?}"));
        let local = dir.join(name);
        assert!(
            local.is_file(),
            "ZKMINER_RISC0_GUESTS_DIR: {} is missing {name}, which methods.rs names",
            dir.display()
        );
        println!("cargo:rerun-if-changed={}", local.display());
        out.push_str(&line[..start - 1]);
        out.push_str(&format!("{:?}", local.display().to_string()));
        out.push_str(&line[end + 1..]);
        out.push('\n');
        if is_elf {
            guests += 1;
        }
    }
    assert!(
        guests > 0,
        "ZKMINER_RISC0_GUESTS_DIR: {} names no guest binaries",
        methods_src.display()
    );

    let out_dir = std::env::var("OUT_DIR").unwrap();
    std::fs::write(std::path::Path::new(&out_dir).join("methods.rs"), out)
        .expect("failed to write methods.rs");
}
