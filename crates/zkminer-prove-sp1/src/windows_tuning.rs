//! Windows-only SP1 tuning, settled once at worker startup (before the server is forked, which
//! inherits this process's environment).

/// The wrap prover's persistent proving key (`SP1_WRAP_PERSISTENT_PK`) on a 16 GB Intel card.
///
/// `sp1-gpu-server` keeps the Groth16/PLONK key between proofs only on cards with 24 GB or more,
/// because on a 16 GB Radeon RX 9070 XT the key's memory slowed the rest of each proof by more than
/// it saved. On a 16 GB Arc A770 (SYCL) it is the other way round: about 2 s less per proof
/// (chacha-mix 38 -> 37 s, sha256-chain 152.1 -> 150.1 s, every proof verified). So with the SYCL
/// server (`SP1_GPU_SERVER_NAME=sp1-gpu-server-sycl`) and at least 15 GiB of card memory it is
/// turned on. A value the operator set wins; a 12 GB B580 is left alone (not measured).
pub(crate) fn apply_sycl_wrap_persistent_pk(vram_bytes: Option<u64>) {
    const VAR: &str = "SP1_WRAP_PERSISTENT_PK";
    if std::env::var_os(VAR).is_some() {
        return;
    }
    let sycl = std::env::var("SP1_GPU_SERVER_NAME").is_ok_and(|n| n == "sp1-gpu-server-sycl");
    if sycl && vram_bytes.is_some_and(|b| b >= 15 << 30) {
        tracing::info!("SP1 tuning: {VAR}=1 (16 GB Intel card: the wrap key stays on the card)");
        // SAFETY: single-threaded startup, before any prover, server or thread exists.
        unsafe { std::env::set_var(VAR, "1") };
    }
}
