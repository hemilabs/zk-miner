fn main() {
    if std::env::var_os("CARGO_FEATURE_MACOS").is_some() {
        embed_macos_guests();
        return;
    }
    // The Intel worker loads its SYCL kernels from shared libraries the risc0 -sys crates build (and
    // oneAPI's SYCL runtime), none of which is on the system's search path and none of which the build
    // gives an rpath. Look for them in `zkminer-intel/lib/` next to the binary, where
    // `scripts/stage-intel-worker-libs.sh` puts them, so a staged worker runs without
    // LD_LIBRARY_PATH. DT_RPATH, not DT_RUNPATH: the kernel
    // libraries load libsycl themselves and have no search path of their own, and only an RPATH on the
    // executable applies to its libraries' dependencies too.
    if std::env::var_os("CARGO_FEATURE_INTEL").is_some() {
        println!(
            "cargo:rustc-link-arg-bin=zkminer-prove-risc0-intel=-Wl,--disable-new-dtags,-rpath,$ORIGIN/zkminer-intel/lib:$ORIGIN"
        );
    }
    // The ROCm worker's HIP runtime: the release ships the one it is compiled against (ROCm 7.1) in
    // `zkminer-rocm/lib/` next to the binary (Dockerfile.build, build-rocm), so a host needs only the
    // amdgpu kernel driver, and a distribution's own ROCm is never picked up instead.
    // DT_RPATH, which ld.so searches before LD_LIBRARY_PATH and the system directories; the runtime's
    // own libraries find each other through their $ORIGIN-relative RUNPATHs. Without that directory
    // (a development build) the system's HIP runtime is used, as before.
    if std::env::var_os("CARGO_FEATURE_ROCM").is_some() {
        println!(
            "cargo:rustc-link-arg-bin=zkminer-prove-risc0-rocm=-Wl,--disable-new-dtags,-rpath,$ORIGIN/zkminer-rocm/lib"
        );
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

fn embed_macos_guests() {
    assert!(std::env::var_os("RISC0_SKIP_BUILD").is_none(), "macOS acceptance rejects guest stubs");
    println!("cargo:rerun-if-env-changed=ZKMINER_RISC0_GUEST_DIR");
    let dir = std::path::PathBuf::from(std::env::var_os("ZKMINER_RISC0_GUEST_DIR")
        .expect("build the authentic Mac guests first and set ZKMINER_RISC0_GUEST_DIR"));
    let mut code = String::new();
    for (name, constant) in [("fibonacci", "FIBONACCI"), ("sha256-chain", "SHA256_CHAIN")] {
        let path = dir.join(format!("{name}.bin")).canonicalize().expect("missing packed guest");
        let bytes = std::fs::read(&path).expect("cannot read packed guest");
        let id = risc0_binfmt::compute_image_id(&bytes).expect("invalid packed guest");
        code.push_str(&format!("pub const {constant}_ELF: &[u8] = include_bytes!({path:?});\npub const {constant}_ID: [u32; 8] = {:?};\n", id.as_words()));
        println!("cargo:rerun-if-changed={}", path.display());
    }
    std::fs::write(std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("methods.rs"), code)
        .expect("cannot write guest metadata");
}
