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

/// Fewer and cheaper device-to-host readbacks for the HIP server (AMD cards).
///
/// On Windows each small readback costs several times what it does on Linux: on an RX 9070 XT the
/// ~14,000 readbacks of a 144M-cycle proof took 7-8x their time on an RTX 4090, 18-26% of the AMD
/// card's GPU time. Two `sp1-gpu-server` switches cut that:
/// - `SP1_GPU_GKR_DEVICE_ROUNDS=1`: a LogUp-GKR layer's later sumcheck rounds finish and sample their
///   challenge on the device; the host replays them and checks every message and challenge;
/// - `SP1_HIP_PINNED_READBACK=1`: the remaining small readbacks go through a pinned staging buffer
///   (off by default on Windows since an RX 9060 XT read back wrong GKR values with it in 18 of 156
///   proofs, each caught by shard verification and proved again).
///
/// RX 9070 XT (SP1's node bench, 4 proofs each): fibonacci 144M-cycle core 2.82-2.86 -> 2.59-2.61 s,
/// sha2 compressed 3.58-3.60 -> 3.18-3.19 s; 150 of 150 proofs verified with no shard retried. A value
/// the operator set wins.
pub(crate) fn apply_hip_readbacks() {
    if crate::warmup::server_name() != "sp1-gpu-server-hip" {
        return;
    }
    for var in ["SP1_GPU_GKR_DEVICE_ROUNDS", "SP1_HIP_PINNED_READBACK"] {
        if std::env::var_os(var).is_none() {
            tracing::info!("SP1 tuning: {var}=1 (AMD card on Windows: fewer, cheaper readbacks)");
            // SAFETY: single-threaded startup, before any prover, server or thread exists.
            unsafe { std::env::set_var(var, "1") };
        }
    }
}

/// Keep the trace LDEs on a 16 GB AMD card (`SP1_GPU_DROP_LDES=0`).
///
/// `sp1-gpu-server` drops a shard's low-degree extensions after its trace commit and re-encodes them
/// later on every card of 20 GB or less, trading time for memory. On Windows a 16 GB HIP card proves
/// at most 2^27-element shards (no device memory arena there), and with the LDEs kept an RX 9070 XT
/// peaked at 13.8 GiB of its 15.06 GiB video memory budget. Through zk-miner, every proof verified:
/// sha256-chain (213M cycles) 62-64 -> 57-59 s, chacha-mix 19-20 -> 17-18 s; SP1's node bench,
/// 720M-cycle fibonacci: core 11.30 -> 10.40 s, compressed 19.08 -> 17.84 s. A card that also drives
/// a display gets a smaller budget, and the server then proves 2^26-element shards, whose LDEs take
/// half the memory (not measured). From 15 GiB of card memory; a value the operator set wins.
pub(crate) fn apply_hip_keep_ldes(vram_bytes: Option<u64>) {
    const VAR: &str = "SP1_GPU_DROP_LDES";
    if std::env::var_os(VAR).is_some() || crate::warmup::server_name() != "sp1-gpu-server-hip" {
        return;
    }
    if vram_bytes.is_some_and(|b| b >= 15 << 30) {
        tracing::info!("SP1 tuning: {VAR}=0 (16 GB AMD card on Windows: the LDEs stay on the card)");
        // SAFETY: single-threaded startup, before any prover, server or thread exists.
        unsafe { std::env::set_var(VAR, "0") };
    }
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
