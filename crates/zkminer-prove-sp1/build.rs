/// The guests `main.rs` embeds, each as `SP1_ELF_<name>-sp1-guest`.
const EMBEDDED_GUESTS: [&str; 6] = [
    "fibonacci",
    "sha256-chain",
    "ecdsa-verify",
    "bigint-mul",
    "memory-merkle",
    "chacha-mix",
];

fn main() {
    println!("cargo:rerun-if-env-changed=ZKMINER_SP1_GUESTS_DIR");
    // Embed guests built elsewhere: Succinct's toolchain, which compiles them, has no Windows build.
    if let Some(dir) = std::env::var_os("ZKMINER_SP1_GUESTS_DIR") {
        import_prebuilt_guests(std::path::Path::new(&dir));
        return;
    }

    // Note: with SP1_SKIP_PROGRAM_BUILD, sp1_build::build_program only sets the SP1_ELF_* env vars
    // for include_elf!, to where the ELFs would be; it creates none, so they must already exist.
    let guest_dir =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../zkminer-prover/guests/sp1");

    // Build SP1 guest programs
    let fibonacci_dir = guest_dir.join("fibonacci");
    if fibonacci_dir.exists() {
        sp1_build::build_program(&fibonacci_dir.to_string_lossy());
    }

    let sha256_dir = guest_dir.join("sha256-chain");
    if sha256_dir.exists() {
        sp1_build::build_program(&sha256_dir.to_string_lossy());
    }

    let ecdsa_dir = guest_dir.join("ecdsa-verify");
    if ecdsa_dir.exists() {
        sp1_build::build_program(&ecdsa_dir.to_string_lossy());
    }

    let bigint_dir = guest_dir.join("bigint-mul");
    if bigint_dir.exists() {
        sp1_build::build_program(&bigint_dir.to_string_lossy());
    }

    let merkle_dir = guest_dir.join("memory-merkle");
    if merkle_dir.exists() {
        sp1_build::build_program(&merkle_dir.to_string_lossy());
    }

    let chacha_dir = guest_dir.join("chacha-mix");
    if chacha_dir.exists() {
        sp1_build::build_program(&chacha_dir.to_string_lossy());
    }

    let torture_dir = guest_dir.join("rv32im-torture");
    if torture_dir.exists() {
        sp1_build::build_program(&torture_dir.to_string_lossy());
    }

    let edge_arith_dir = guest_dir.join("edge-case-arith");
    if edge_arith_dir.exists() {
        sp1_build::build_program(&edge_arith_dir.to_string_lossy());
    }

    let mem_stress_dir = guest_dir.join("memory-stress");
    if mem_stress_dir.exists() {
        sp1_build::build_program(&mem_stress_dir.to_string_lossy());
    }

    let precompile_dir = guest_dir.join("precompile-interleave");
    if precompile_dir.exists() {
        sp1_build::build_program(&precompile_dir.to_string_lossy());
    }

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
    let seg_boundary_dir = guest_dir.join("segment-boundary");
    if seg_boundary_dir.exists() {
        sp1_build::build_program(&seg_boundary_dir.to_string_lossy());
    }

    let minimal_dir = guest_dir.join("minimal-proof");
    if minimal_dir.exists() {
        sp1_build::build_program(&minimal_dir.to_string_lossy());
    }

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
        guest_dir.join("minimal-proof/src/main.rs").display()
    );
}

/// Points each embedded guest's `SP1_ELF_*` at `<dir>/<name>-sp1-guest`: the ELFs a build of this
/// crate with Succinct's toolchain produced, under the names sp1_build gives them.
fn import_prebuilt_guests(dir: &std::path::Path) {
    for guest in EMBEDDED_GUESTS {
        let name = format!("{guest}-sp1-guest");
        let elf = dir.join(&name);
        assert!(
            elf.is_file(),
            "ZKMINER_SP1_GUESTS_DIR: {} has no {name}",
            dir.display()
        );
        println!("cargo:rerun-if-changed={}", elf.display());
        println!("cargo:rustc-env=SP1_ELF_{name}={}", elf.display());
    }
}
