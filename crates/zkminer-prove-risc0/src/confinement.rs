//! Workers that run requester guests are confined (`zkminer_witness_sandbox::confine`).
//!
//! The first command that runs a guest or uses the GPU (`Execute`, `Prove`, `ProgramId`,
//! `Benchmark`, `CalibrateSegmentLimit`, the Intel warm-up's proof, `--benchmark`) first confines
//! this process, every thread it has and everything it starts, for the rest of its life ([`confine`]):
//!
//! - no socket of any kind, Unix ones included (the CUDA driver's own listener, which it opens at
//!   `cuInit`, is opened first and can accept nothing);
//! - read access to the system's files, this binary's directory, `LD_LIBRARY_PATH`, the
//!   `risc0-groth16` component (`RISC0_HOME`, `RISC0_GROTH16_DIR`) and, for CUDA, the driver's JIT
//!   cache; write access to a private temporary directory (`TMPDIR`, made at startup by [`prepare`]),
//!   to its proofs' segment directory (`crate::segments`) and to the GPU caches the build needs
//!   (CUDA: risc0's Groth16 cache; Intel: the SYCL and compute-runtime kernel caches); the GPU
//!   device nodes. Nothing else of the home directory;
//! - no signal to, or `/proc` access to, the miner or another worker.
//!
//! The one-time setup that needs the network (the `risc0-groth16` component's download in
//! `Warmup`) runs before; a `Warmup` after refuses rather than download, and the miner runs it on a
//! fresh worker. Where the Groth16 wrap needs Docker (the CPU build, or Intel with
//! `RISC0_GROTH16_INTEL_PROVER=docker`), a helper process started before the confinement does it
//! (`groth16_wrap`): it never runs a guest, and accepts from the worker only a strictly checked
//! prover input, which the worker makes from its seal.
//!
//! An error means no guest may run: the caller answers the command with it.

#[cfg(target_os = "linux")]
mod imp {
    use std::path::PathBuf;
    use std::sync::OnceLock;

    use zkminer_witness_sandbox::confine::{self, Confinement, Rights, Sockets};

    /// The private temporary directory [`prepare`] made.
    static TMPDIR: OnceLock<PathBuf> = OnceLock::new();
    /// The temporary directory before [`prepare`] pointed `TMPDIR` at the private one.
    static ORIGINAL_TMPDIR: OnceLock<PathBuf> = OnceLock::new();

    /// The temporary directory this process was started with: outside every path the confined
    /// worker may write (the Docker Groth16 helper works there).
    pub fn original_tmpdir() -> PathBuf {
        ORIGINAL_TMPDIR
            .get()
            .cloned()
            .unwrap_or_else(std::env::temp_dir)
    }

    /// At startup, while the process has one thread: a private temporary directory, which `TMPDIR`
    /// then names for everything in this process (risc0's Groth16 work directories, SYCL's).
    pub fn prepare() {
        let _ = ORIGINAL_TMPDIR.set(std::env::temp_dir());
        match confine::private_tmpdir("risc0") {
            Ok(dir) => {
                // SAFETY: called from `main` before any thread exists.
                unsafe { std::env::set_var("TMPDIR", &dir) };
                let _ = TMPDIR.set(dir);
            }
            // Before logging is set up.
            Err(e) => eprintln!(
                "cannot make a private temporary directory ({e}); this worker will refuse to run \
                 guests"
            ),
        }
    }

    pub fn is_confined() -> bool {
        confine::is_active()
    }

    pub fn confine() -> Result<(), String> {
        if confine::report().is_some() {
            // Confined already: the sockets and the filesystems within reach, again.
            return confine::recheck().map_err(|e| e.to_string());
        }
        let tmp = TMPDIR
            .get()
            .ok_or("no private temporary directory to confine this worker to")?;
        crate::groth16_wrap::start_helper_if_needed()?;
        pre_init_gpu();
        let c = policy(tmp);
        let report = confine::confine_all_threads(&c).map_err(|e| e.to_string())?;
        tracing::info!("worker confined: {report}");
        Ok(())
    }

    fn home() -> Option<PathBuf> {
        dirs::home_dir()
    }

    /// `$XDG_CACHE_HOME`, else `~/.cache`.
    fn cache_home() -> Option<PathBuf> {
        std::env::var_os("XDG_CACHE_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| home().map(|h| h.join(".cache")))
    }

    /// A cache directory the confined worker writes: made now (once confined it could not make it).
    fn writable_cache(c: &mut Confinement, dir: PathBuf) {
        let _ = std::fs::create_dir_all(&dir);
        c.allow(dir, Rights::WRITE);
    }

    fn policy(tmp: &std::path::Path) -> Confinement {
        let mut c = Confinement::with_system(Sockets::None);
        if let Some(dir) = std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(PathBuf::from))
        {
            c.allow(dir, Rights::READ);
        }
        for dir in confine::library_path_dirs() {
            c.allow(dir, Rights::READ);
        }
        c.allow(tmp, Rights::WRITE);
        // Its proofs' segment files (segments.rs), made at startup.
        if let Some(dir) = crate::segments::dir() {
            c.allow(dir, Rights::WRITE);
        }
        // The risc0-groth16 component: rzup's home and the component itself.
        match std::env::var_os("RISC0_HOME") {
            Some(h) => {
                c.allow(PathBuf::from(h), Rights::READ);
            }
            None => {
                if let Some(h) = home() {
                    c.allow(h.join(".risc0"), Rights::READ);
                }
            }
        }
        if let Some(dir) = std::env::var_os("RISC0_GROTH16_DIR") {
            c.allow(PathBuf::from(dir), Rights::READ);
        }
        // Witness proofs: `W` from the retention store, segments to their directory (made now).
        {
            use zkminer_prover_protocol::types::{WITNESS_READ_DIR_ENV, WITNESS_SEGMENT_DIR_ENV};
            if let Some(dir) = std::env::var_os(WITNESS_READ_DIR_ENV).filter(|d| !d.is_empty()) {
                c.allow(PathBuf::from(dir), Rights::READ);
            }
            if let Some(dir) = std::env::var_os(WITNESS_SEGMENT_DIR_ENV).filter(|d| !d.is_empty()) {
                let dir = PathBuf::from(dir);
                let _ = std::fs::create_dir_all(&dir);
                c.allow(dir, Rights::WRITE);
            }
        }
        if cfg!(any(feature = "cuda", feature = "rocm", feature = "intel")) {
            c.allow_gpu_devices();
        }
        if cfg!(feature = "rocm") {
            // ROCm starts its threads with a CPU set, which glibc applies by thread id.
            c.allow_thread_affinity();
        }
        if cfg!(feature = "cuda") {
            // The driver's JIT cache: read only. This build carries code for its cards, so nothing
            // is compiled; a write that fails is only not cached.
            match std::env::var_os("CUDA_CACHE_PATH") {
                Some(p) => {
                    c.allow(PathBuf::from(p), Rights::READ);
                }
                None => {
                    if let Some(h) = home() {
                        c.allow(h.join(".nv"), Rights::READ);
                    }
                }
            }
            // risc0's Groth16 prover keeps its derived data here (kernels/cuda/disk_cache.cuh).
            if let Some(dir) = std::env::var_os("RISC0_G16_CACHE_DIR")
                .map(PathBuf::from)
                .or_else(|| cache_home().map(|c| c.join("risc0-groth16")))
            {
                writable_cache(&mut c, dir);
            }
        }
        if cfg!(feature = "intel") {
            // SYCL and the compute runtime compile kernels on first use and cache them; the
            // warm-up fills these (see `warm_up`).
            for (var, name) in [
                ("SYCL_CACHE_DIR", "libsycl_cache"),
                ("NEO_CACHE_DIR", "neo_compiler_cache"),
            ] {
                if let Some(dir) = std::env::var_os(var)
                    .map(PathBuf::from)
                    .or_else(|| cache_home().map(|c| c.join(name)))
                {
                    writable_cache(&mut c, dir);
                }
            }
        }
        c
    }

    /// The CUDA driver opens a Unix socket of its own at initialisation (a listener for sharing
    /// unified memory), which a process without sockets could not: initialise it first. Once it is
    /// up, nothing in it needs a new socket (contexts, streams, resets alike).
    fn pre_init_gpu() {
        #[cfg(feature = "cuda")]
        {
            // SAFETY: dlopen/dlsym with NUL-terminated names; cuInit takes a flags word.
            unsafe {
                let lib =
                    libc::dlopen(c"libcuda.so.1".as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL);
                if lib.is_null() {
                    tracing::warn!(
                        "no CUDA driver (libcuda.so.1) to initialise before confinement"
                    );
                    return;
                }
                let sym = libc::dlsym(lib, c"cuInit".as_ptr());
                if sym.is_null() {
                    return;
                }
                let cu_init: extern "C" fn(u32) -> i32 = std::mem::transmute(sym);
                let rc = cu_init(0);
                if rc != 0 {
                    tracing::warn!("cuInit failed before confinement: {rc}");
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use imp::{confine, is_confined, original_tmpdir, prepare};

/// No Landlock or seccomp off Linux: nothing to confine with.
#[cfg(not(target_os = "linux"))]
pub fn confine() -> Result<(), String> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn is_confined() -> bool {
    false
}

#[cfg(not(target_os = "linux"))]
pub fn prepare() {}

#[cfg(not(target_os = "linux"))]
pub fn original_tmpdir() -> std::path::PathBuf {
    std::env::temp_dir()
}
