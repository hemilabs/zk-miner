//! Windows-only SP1 tuning, settled once at worker startup (before the server is forked, which
//! inherits this process's environment).

/// SP1's GPU Groth16 prover (`groth16_gpu_helper`) for the CUDA server.
///
/// Without it, `sp1-gpu-server` proves the final Groth16 wrap with gnark on the CPU ("Groth16
/// prover: gnark CPU (groth16_gpu_helper was not found ...)"). The Windows NVIDIA release ships the
/// helper beside this worker; the server looks for it beside itself (`~/.sp1/bin`, shared by every
/// vendor's server build) or at `SP1_GROTH16_GPU_HELPER`, so it is pointed at with the variable,
/// for the CUDA server only: an AMD or Intel card's server must not pick up a CUDA build. On an RTX
/// 4090: chacha-mix 21.3 -> 16.2 s a proof, the Groth16 step ~14.7 -> ~9.5 s. A value the operator
/// set wins.
pub(crate) fn apply_cuda_groth16_helper() {
    const VAR: &str = "SP1_GROTH16_GPU_HELPER";
    if std::env::var_os(VAR).is_some() || !crate::warmup::drives_cuda() {
        return;
    }
    let Some(helper) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("groth16_gpu_helper.exe")))
        .filter(|path| path.is_file())
    else {
        return;
    };
    tracing::info!("SP1 tuning: {VAR}={} (the GPU Groth16 prover)", helper.display());
    // SAFETY: single-threaded startup, before any prover, server or thread exists.
    unsafe { std::env::set_var(VAR, &helper) };
}

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
