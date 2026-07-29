# Intermittent invalid multi-segment proofs

## Symptom
On **large proofs that split into multiple segments** (~1M cycles/segment at po2=20),
the prover occasionally produces a proof that **fails its own segment verification** —
`verify segment: verification indicates proof is invalid` → `ProofFailed`.

It is **nondeterministic**: the same guest + same input + same binary is valid on one
run and invalid on the next. The **journal (output) is always correct** — only the
cryptographic proof is bad. **Single-segment proofs never show it.** The failure rate
scales with segment count.

That profile — nondeterministic, journal-correct, multiple unrelated guests,
multi-segment only — is the signature of a **kernel-level race / memory-ordering bug in
the GPU proving path**, not a circuit/constraint or guest bug.

## There are TWO distinct root causes

### 1. ROCm / RDNA3 (RX 7900 XTX, gfx1100) — identified and fixed
- **Root cause:** sppark's `__syncwarp()` HIP polyfill (in `util/cuda2hip.hpp`) used
  `__builtin_amdgcn_wave_barrier()`, which only **reconverges** the wavefront — it does
  **not** emit the `s_waitcnt lgkmcnt(0)` that orders LDS/shared-memory traffic. The NTT
  transpose (`ntt/kernels.cu`: write shared `xchg` → `__syncwarp` → cross-lane read) then
  raced on RDNA3, corrupting trace/DEEP polynomials → intermittent invalid STARK proofs.
  Measured ~10–20% on `babybear_stress_scale`, ~33% on `precompile_interleave_multiseg`.
- **Fix:** risc0-sppark `c5d2d7a2` (branch `max/amd_support`) adds
  `__builtin_amdgcn_fence(__ATOMIC_ACQ_REL, "workgroup")` before the wave barrier, which
  lowers to the missing LDS waitcnt. After a clean rebuild: **40/40 valid** (was ~20%).
- **Two gotchas that will bite an independent investigation:**
  - **Version:** the build recipe (`gpu-builds` memory) records sppark HEAD as `6be0997`,
    which is the **pre-fix** commit. The fix is `c5d2d7a2`. Verify the actual ROCm worker
    binary was built from `c5d2d7a2` or later — if it's `6be0997`, the bug is still present.
  - **Stale kernel cache:** the persistent `eval_check_cache_rocm` keys compiled kernel
    objects on a hash that **does not include `cuda2hip.hpp`'s contents**. So editing that
    header (or bumping to the fixed commit) does **not** invalidate
    `remaining_kernels_rocm.o` / `ffi_supra.o`. You must
    `rm -rf target/<dir>/release/eval_check_cache_rocm` **and**
    `cargo clean -p risc0-circuit-rv32im-sys` (one `-p` per package — multi-package
    `clean -p a b c` silently no-ops) for the change to take effect. This caused a false
    "residual 1/15" once.

### 2. CUDA / Blackwell (RTX 5090) — still OPEN, different root cause
During a hardened full-suite run, `test_bigint_mul_risc0` (heavy 128×128 schoolbook
multiply, multi-segment) hit the **same** `invalid` error **once** on the 5090, then
passed 3/3 on immediate retry. This is a **separate** bug: CUDA has a native `__syncwarp`,
so the RDNA3 LDS-fence root cause does not apply. It is much rarer (earlier CUDA runs were
26/26 clean) and looks like a **residual multi-segment race** in the shared proving path.
This is the one genuinely worth a fresh upstream look — it is not explained by the ROCm fix.

> When we say "affects both the 5090 and the 7900 XTX," those are **two different bugs**
> that share one surface symptom. Do not assume fixing one addresses the other.

## How to reproduce (for bisecting)
- **ROCm repro:** `babybear_stress_scale` (iters=5000, no precompiles — rules out the
  SHA-256 path) and `precompile_interleave_multiseg` (n=2000). Run each ~10–20× and count
  invalids.
- **CUDA repro:** `test_bigint_mul_risc0` (n=64), multi-segment — expect a *low* rate, so
  you need many runs.
- **Controls that should always pass:** single-segment variants (e.g. `babybear` iters=100).
- Harness + build/run details are in the `zkvm-test-build-run` and `gpu-builds` memory notes.

## Already ruled out
- **Not** the SHA-256 corruption fix (`53d2d0fc`) — babybear uses no SHA-256 and still failed pre-fence.
- **Not** eval_check↔witgen pipelining — the AMD build force-syncs and it still failed.
- Prime suspects for the **remaining CUDA** case: a residual wavefront/warp-sync or
  uninitialized-memory race in the **multi-segment STARK path** (segment stitching /
  DEEP-ALI / NTT) — state that only manifests when more than one segment is proved.

## Related but separate: 4090 (Ada) OOM on large proofs
The RTX 4090 (24 GB) historically `WORKER_DIED` on these proof sizes — that was **not** the
invalid-proof bug and **not** a true capacity issue. Root cause: the dispatcher set
`CUDA_VISIBLE_DEVICES` to a PCI bus id, so both CUDA workers pinned to GPU 0 (the 5090) and
double-booked it to OOM while the 4090 sat idle. Fixed via the numeric device index; the
4090 peaks ~18.5 GB on these proofs (24 GB is plenty). See the `gpu-pinning-oom` memory note.

## Reproduction data (2026-07-08, exhaustive per-GPU sampling)
Ran `babybear-stress` at high segment counts on each GPU, N runs each, classifying every
proof VALID / INVALID_PROOF / OOM-DIED(crash) / OTHER (test:
`comprehensive_zkvm_test::sampling_multiseg_per_gpu`, `SAMPLE_GUEST/ITERS/RUNS` env knobs).

**Segment scaling of the invalid-proof (NVIDIA, ~140 segments, iters=33000, 100 runs):**

| GPU | valid | INVALID_PROOF | crash (OOM/DIED) |
|-----|-------|---------------|------------------|
| RTX 5090 (Blackwell, sm_120) | 80/100 | **4 (4%)** | **16 (16%)** |
| RTX 4090 (Ada, sm_89)        | 97/100 | **2 (2%)**  | 1 (1%) |

- At ~20 segments (iters=5000) the invalid-proof was near-invisible; at ~65 segments (iters=15000)
  still clean over ~25 runs; at **~140 segments it clearly reproduces on BOTH NVIDIA cards** →
  strong confirmation the invalid-proof **scales with segment count**.
- Exact error text captured: `Worker proof error (ProofFailed): verify segment: verification
  indicates proof is invalid`.
- The invalid-proof is a **per-proof race** — reproduces regardless of run duration.

**The 5090 crash is a SEPARATE, environmental phenomenon (do not conflate with the invalid-proof):**
- 16% in the 10h/100-run, but **0/15 in a fresh ~93-min run** (P≈7% if independent) → not per-proof-random.
- Crashes were **clustered** in consecutive rounds (2–6, 13–16, 26–29) and each died at ~210–262s,
  *longer* than a valid proof (~160–202s). NOT host-RAM OOM (170 GB free, no OOM-killer) and NOT
  VRAM OOM (5090 has the most VRAM, 14 GB free). Reads as a **thermal / driver / sustained-state**
  crash under long load — a different bug from the invalid-proof, and 5090/Blackwell-specific.
- Raw crash signature still uncaptured (didn't fire in the short run); needs a long sustained run
  with the now-added raw-error logging + GPU temp/power correlation.

**Host env for the runs:** 191 GB RAM, no swap; RTX 5090 32 GB, RTX 4090 24 GB, 4090 peaks well
under 24 GB even at ~140 segments (no VRAM OOM).

## ROOT CAUSE (2026-07-08, found via compute-sanitizer initcheck)
The intermittent multi-segment invalid-proof is an **uninitialized witness-buffer read** in
`eltwise_zeroize_fp`, NOT the eval_check↔witgen pipeline (that hypothesis was disproven — forcing
`needs_sync=true` and rebuilding left the 4090 at ~1 invalid/22 runs, with *identical* timing, i.e.
a no-op).

Evidence chain:
- `compute-sanitizer --tool initcheck` on a multi-segment proof flags exactly one segment-path
  uninitialized `__global__` read (4 bytes): `eltwise_zeroize_fp(Fp*)+0x70`, called from
  `WitnessGenerator::new` → `SegmentProver::prove_begin`. (A *single*-segment proof shows only an
  unrelated groth16 alt_bn128 MSM uninit read — see below — never this one.)
- The kernel (`risc0/sys/kernels/zkp/cuda/eltwise.cu:72`):
  ```
  Fp val = elems[idx];          // reads the cell
  elems[idx] = val.zeroize();
  ```
  and `Fp::zeroize()` (`fp.h:106`) only maps the INVALID sentinel (0xffffffff) → 0 and **keeps any
  other value**. The design assumes every witness cell is either written by witgen or still holds
  INVALID (so it becomes 0).
- The witness buffers come from a **reuse pool** (`cuda.rs` BUFFER_POOL, "cache for reuse instead of
  cuMemFree"). `MetaBuffer::new` INVALID-fills via `alloc_elem_init(.., Val::INVALID)` (`set_32`),
  but initcheck proves a cell is still uninitialized at zeroize time — so the INVALID fill is not
  fully covering the range `eltwise_zeroize_elem` reads (`elems.size()`) on a reused buffer.
- Net: on multi-segment (buffer reuse), a cell witgen didn't write holds **stale, non-INVALID data
  from a prior segment**; `zeroize` preserves it → corrupt witness → the segment's STARK proof fails
  its own verification. Nondeterministic (depends whether the stale value ≠ INVALID), multi-segment
  only (fresh single-segment buffers don't have the stale non-INVALID cell), journal stays correct
  (execution is fine; only the witness is corrupt). Scales with segment count (more reuses).

**Fix attempt #2 FAILED (2026-07-08).** Hypothesis: the CUDA HAL's INVALID fill (`alloc_elem_init` via
cust `set_32`) races the persistent-stream kernels on a reused buffer, unlike the HIP HAL which fills
via `risc0_zkp_cuda_fill_u32` on the persistent stream. Changed CUDA `alloc_elem_init` /
`alloc_extelem_zeroed` to match HIP, rebuilt, retested → **still ~1 invalid / 10 runs**, and re-running
initcheck on the fixed binary shows the **same `eltwise_zeroize_fp` uninit read persists**. So the
uninitialized memory does NOT come from the witness-buffer fill — the fill covers the buffer. It is
**propagated from upstream**: `generate_witness`/`scatter` reads uninitialized device memory and writes
it into the witness buffer, and initcheck reports the eventual read *sink* at `eltwise_zeroize` rather
than the write origin. The deterministic read + ~2–6% corruption is still consistent with the
"only corrupts when the stale value ≠ INVALID" mechanism, so this remains the best lead — but the true
origin (and fix) is upstream of the fill.

**Sanitizer chain results (2026-07-08, exhaustive):**
- **racecheck**: 6 error-races in `_GS_NTT` (BabyBear GS-NTT, `gs_mixed_radix_wide.cu`). RULED OUT as
  the cause — the identical race appears on **single-segment** proofs (which always pass), so it's not
  the multi-segment-specific culprit (likely a racecheck over-report of a `__syncthreads`-protected
  exchange; synccheck is clean).
- **synccheck**: clean (no barrier-divergence / invalid-sync).
- **initcheck**: the `eltwise_zeroize_fp` uninit read is **confirmed real** — 24 reads on a *valid,
  non-OOM* iters=500 multi-seg proof; **0** on single-seg. So it happens on every multi-seg proof and
  the proof passes when the stale values are benign, corrupting only when a stale cell ≠ INVALID
  (~2-6%). Localized to **witness-buffer pool reuse** on the 2nd+ segment (`WitnessGenerator::new`).
- Second (separate, benign) uninit read: groth16 BN254 MSM `integrate<alt_bn128>` — on every proof.

**WALL (unresolved).** The buffer pool (`cuda.rs` BUFFER_POOL) caches by exact byte size and returns
exact-size buffers; `alloc_elem_init` fills `size` elements and `eltwise_zeroize_elem` reads `size`
elements, on the same persistent stream — so by source inspection the reused buffer *is* fully filled,
yet initcheck reports an uninitialized cell (e.g. element 128) on reused buffers only. Every concrete
hypothesis was falsified: not u32 count overflow (buffer is ~hundreds of MB at po2=20), not a
fill-stream mismatch (fix #3 changed the fill to the persistent stream — uninit persisted), not an
OOM/memory-stress artifact (reproduced clean at iters=500), not an untracked driver-API memset
(single-seg uses the same fill and shows no uninit). The gap is between initcheck's tracking of pooled
memory and the fill — resolving it needs upstream risc0/sppark knowledge of the witgen buffer lifecycle
+ CUDA HAL pool, or GPU/compiler-level tooling beyond what's available here.

**Status: 3 fixes failed** (pipeline no-op; witness-fill-stream; and the fill-stream persisted the
uninit). The reproducer + the confirmed multi-segment-specific `eltwise_zeroize`←witgen uninitialized
read + the ruled-out NTT race + the exact mechanism are a strong, actionable upstream bug report for
`hemilabs/risc0`. Recommend filing upstream rather than more local rebuild-guess cycles.

**If continuing locally:** the only untried defensive fix is a *synchronous* full-buffer INVALID memset
(`cudaMemset(buf, 0xff, bytes)`, runtime API, + device sync) of code/data right before witgen, to
force-cover any cell the async fill misses on reuse — a guess (given the source says the fill already
covers), needing a rebuild + exhaustive retest.

**Prior fix direction (superseded/wrong):** "fix the witness-buffer INVALID fill coverage/stream" — the
fill was not the source.

## Secondary bug found the same way (separate, likely benign)
Every proof (incl. single-segment) has a deterministic uninitialized `__global__` read (16 bytes) in
sppark's BN254 MSM `integrate<...alt_bn128...>` during `succinct_to_groth16` shrink-wrap. Single-
segment proofs pass despite it, so it's not the invalid-proof cause, but it's a real bug worth an
upstream report.

## Suggested first steps
1. Confirm which sppark commit each deployed worker binary was built from (`c5d2d7a2`+ for
   ROCm) and that the cache was cleared — this may fully close the ROCm side.
2. Treat the CUDA invalid-proof (both Ada + Blackwell) as a separate upstream report against
   `hemilabs/risc0` (`max/cdna`): minimal multi-segment repro, note it is absent from the LDS-fence
   fix, scales with segment count, point at the shared multi-segment path (prime suspect: the
   eval_check↔witgen stream pipelining, which is force-synced on AMD but active on CUDA).
3. Treat the 5090 crash-under-sustained-load as a THIRD, separate issue (thermal/driver), not part
   of the invalid-proof root cause.
