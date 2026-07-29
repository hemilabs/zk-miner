# Devnet proving-workload examples

Four RISC Zero proving jobs of increasing size, for exercising the miner
end-to-end (claim → prove → fulfill) at a range of proving durations. All four
use the **`chacha-mix`** guest (pure ARX compute — no precompiles, so cycle count
scales linearly with the input iteration count `n`, making proving time cleanly
tunable).

## The examples

Times measured on this host's CUDA GPUs (RTX 5090 / 4090). Proving time is
GPU-dependent — the 5090 is fastest; a slower or busier card runs longer.

| Name | `n` (chacha iters) | ≈ cycles | ≈ segments | measured proving time |
|------|-------------------:|---------:|-----------:|----------------------:|
| `xs` |             16,000 |    27.3M |        ~26 |                 ~33 s |
| `s`  |             34,000 |    57.1M |        ~55 |                 ~65 s |
| `m`  |             90,000 |   151.0M |       ~144 |                ~126 s |
| `l`  |            182,000 |   305.1M |       ~291 |                ~325 s |

Model (CUDA): `proving_time ≈ 3.8 s + 0.00163 × n`, i.e. ~1,678 cycles/iter.
Adjust `n` to hit any target time; e.g. `n = (target_seconds − 3.8) / 0.00163`.

## Prerequisites

- The devnet is deployed (see `scratchpad/devnet2_up.sh`) and its addresses are
  in `scratchpad/devnet2_addrs.env` (`HEMI_PROVE`, `HEMI_TOKEN`, `PROGRAM_ID`).
- The **chacha-mix** guest ELF is cached at the job's programId so the miner
  serves it from cache (no download):
  ```bash
  source scratchpad/devnet2_addrs.env
  cp target/riscv-guest/zkminer-prover/chacha-mix/riscv32im-risc0-zkvm-elf/release/chacha-mix.bin \
     ~/.zkminer/elfs/${PROGRAM_ID}.elf
  ```
- The miner is running and polling (`zkminer run --headless`). Jobs must be
  submitted **after** the miner starts polling (its monitor only sees forward).

## Submitting

```bash
examples/submit_examples.sh            # submit all four (xs, s, m, l)
examples/submit_examples.sh m l        # submit only the 2.5-min and 5-min ones
examples/submit_examples.sh xs xs xs   # three copies of the 30-second one
```

Each job is an open-auction RISC0 job (50–100 HEMI, 2 h fulfillment window). The
running miner detects, claims, proves, and fulfills them — up to one per GPU
concurrently.

## Reliability: retries + VRAM routing

Multi-segment GPU proofs occasionally fail their own segment verification (a
known nondeterministic prover race that scales with segment count) or OOM a
smaller card. The miner handles both automatically (no per-example tuning
needed):

- **Retry on invalid proof** — re-proves up to 3× (the failure is
  nondeterministic, so a retry almost always succeeds). Round-robin may land the
  retry on a different GPU.
- **Route large jobs away from small GPUs** — a job that OOMs/kills a worker is
  retried on a higher-VRAM GPU (≥ 30 GB, i.e. the 32 GB 5090 rather than the
  24 GB 4090). Jobs that commit a large cycle count (`≥ 150M`) are pinned to a
  high-VRAM GPU up front.

In the validation run all four fulfilled with 0 permanent failures (3 automatic
retries fired for the `s` and `l` examples).
