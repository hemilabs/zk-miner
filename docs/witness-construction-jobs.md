# Witness Construction for ZK Proving Jobs

**Status:** Implementation plan.
**Scope:** zkminer (prover), requester tooling, and documentation in the contracts repo (§7.3).
**HemiProve contract changes: none** (§6). Facts are verified against `hemiprove-contracts`
`3bc441dd8`; witness jobs are served only on a deployment whose core pins match that release.
**Author:** Max Sanchez · **Last updated:** 2026-11-16

## 1. Problem

A HemiProve job's witness reaches the prover through `JobDescriptor.inputData`, which the protocol
treats as opaque ("the guest input / a hint for provers (opaque to the protocol; hashed)", in the
INTERACTION_GUIDE's descriptor reference), capped with the other descriptor bytes at 64 KiB. That
works for small inputs and fails for any program whose witness is large, derived, or external:

- **Chain state.** To prove "slot *S* of contract *C* at block *B* holds *V*", or "block *N*
  executes to state root *R*", the guest needs headers, Merkle-Patricia proofs, code, transactions:
  hundreds of KB to many MB, usually not held by the requester. It has to be **queried and shaped**
  from chain RPCs, often adaptively (what to fetch next depends on what the last response said).
- **AI inference.** The guest needs model weights plus the input; the weights live in a content
  store, not on-chain.
- **Any proof over external data** (a dataset, a signed feed, an archive): the bytes the guest
  consumes are produced by a *procedure*, not supplied inline.

We want jobs where the requester ships a **program that constructs the witness**, the miner runs it
**securely** and proves over its output, and **nobody ever has to judge whose fault a failure was**:
no council, no committee, no dispute, no bond.

## 2. Goals and non-goals

**Goals**

- **A requester-written witness builder** with arbitrary logic over brokered data sources, including
  adaptive RPC queries: query, inspect, query again, serialize, return (§9, §12).
- **No fault attribution.** The miner simulates every job end to end before taking a lock and
  refuses anything it cannot prove (§5). No release path, failure reason, bond or council decides who
  caused a failure.
- **Zero HemiProve contract changes** (§6).
- **Soundness independent of the builder and of every data source** (§8). What the requester gets is
  exactly what its guest proves and its binding pins; §7.2 and §8 say how to make that the question
  it meant to ask.
- **Containment:** the builder cannot read keys or secrets, touch the host, reach the internal
  network, or starve the miner's own chain traffic (§10, §14).
- **Operator-controlled data sources:** the requester declares a capability; the operator controls
  the endpoints (§11).

**Non-goals**

- Proving over un-committable, unauthenticated data as a trustless product (§8.7).
- Input privacy against provers: every miner that simulates a job sees its witness (§8.6).
- Replacing the inline-`inputData` path; witness construction is additive and opt-in per job.
- Paying miners for simulation: it is unpaid, like pre-claim measurement today, and each miner bounds
  it locally (§17).

## 3. Glossary

| Term | Meaning |
|---|---|
| `W` | The witness bytes a builder produced; the guest's input after the optional 64-byte prefix |
| `J` | The guest's journal on `prefix ‖ W` |
| po2 | risc0 segment size, log2 of cycles per segment; each card proves at its own po2 |
| `D`, `G` | A lock's deadline and the prover grace after it |
| Caller | `msg.sender` of the submit transaction; the requester is whoever controls it |
| Lock path | Any transaction that gives this host a lock: `claimJob`, `claimJobDelegated`, `slashAndClaim`, `claimAndFulfillAssigned`, `submitBid` + `settleBid` |
| Builder | The requester's program that produces `W`; executed, never proven (§9) |
| Bundle | The immutable retained record a lock is proven from (§15.1) |
| Broker | The host process that performs every fetch for builders and artifacts (§10.1) |
| Artifact endpoint | An operator-configured Hemi RPC used only for `hemi-code` reads (§13) |
| Artifact egress | A non-identifying egress for requester-chosen URLs (Phase 2, §14.3) |
| Operator mirror | An optional operator-configured content store addressed by content id |
| Reservation | The lowest price at which this host takes a lock (§17.2) |
| Trust domain | The job's caller; operator-curated public content is one global domain |
| Profile key | Phase 1: (sorted capability classes and method sets, builder type) |
| Held lock | A lock this host holds, or may hold (claim sent, outcome not yet known) |

## 4. Trust model

| Domain | Who writes it | Trusted for | Enforced by |
|---|---|---|---|
| **In-guest validation** (zkVM) | guest author | *correctness*: the statement proven | the proof + the journal binding |
| **Witness builder** (host side, never proven) | requester | *nothing*: availability and shaping only | the sandbox (§10) and the broker (§11, §14) |
| **Pre-claim simulation** | the miner | *the miner's own safety* | the claim gate (§5) |

**The prover chooses `W`.** The builder is a convenience offered to honest miners; nothing makes a
miner use it, and nothing on-chain records which witness was used. `builderParams` bind nothing (F2).
The guest and the binding are the *entire* specification of what a proof means: every value that
defines the question must be pinned in the binding or re-derived inside the guest from pinned values
and authenticated data (§8.2).

**Every host answer is a prover input.** Anything the zkVM host answers — `sys_rand` (and through it
std's `HashMap`/`HashSet` seeds, `getrandom`, `rand`), `sys_cycle_count`, `getenv`, `argv`, hint
channels, the segment size — is chosen by whoever runs the proof. No journal byte or selection may
depend on it (§8.2).

Adversaries:

- **Malicious requester** — wants to (a) get a false statement accepted, (b) reach internal networks
  or exfiltrate, (c) exhaust miner resources, (d) make a miner's fulfil fail after a lock. (a) is
  closed by the binding and the guest (§8); (b) by the sandbox and broker (§10, §14); (c) is bounded
  by admission (§17); (d) through the job's own content is closed by simulate-before-claim and §6;
  through shared resources or blockspace it is closed by isolation and pre-claim gates, or is a
  residual every inline job carries (§5.5).
- **Malicious or compromised data source** — wrong bytes fail in-guest validation in simulation (no
  lock); hostile bytes hit a sandboxed parser; the broker never forwards error text or headers.
- **Malicious miner** — chooses a favourable `W` or a favourable host answer; the binding and a
  correctly written guest decide payout.
- **Free-riding miner** — copies another miner's claim without simulating (§5.6); it takes its own
  risk and cannot touch a simulating miner's stake.
- **Malicious guest author or poisoned validation library** — publishes a guest or prelude that
  under-validates; the victim is the requester who reused it (§8.3).

## 5. The model: simulate before claim

### 5.1 The rule

A miner takes a witness-job lock by any lock path only after it has, on its own host:

1. run the builder and **persisted** `W` to the retention store (streamed, `sha256(W)` recorded)
   before any execution reads it;
2. executed the guest from that persisted copy on exactly the input it will prove (`W`, after
   `abi.encode(jobId, prover)` when the job carries the journal-prefix marker) at **every po2 it may
   prove at**, with identical journals;
3. checked `J` against the binding exactly as the router judges it, and every claim-gate limit
   (§5.2 step 7); and
4. **published** the bundle (immutable, fsynced) and its **pin** in the retention store before
   signing the lock transaction (§15).

After the lock, the builder never runs again and no data source is contacted for that job: the proof
is of the bundle. A held lock whose store is *unavailable* is kept; one whose bundle is *missing* or
*corrupt* on an available store is handled as §15.2 says.

This is the protocol's own prover checklist (INTERACTION_GUIDE, "Prover checklist: before you
claim": fetch "the full witness (`inputData`, or the off-chain data it points to)", check the binary,
execute, match the binding, check sizes, verifier and gas). Witness construction changes only how
the witness is obtained.

### 5.2 The pipeline

| # | Step | Network | On failure |
|---|---|---|---|
| 0 | Decode the descriptor from the submit transaction; check it hashes to `descriptorHash` | chain | skip |
| 1 | Classify: `inputData` starts with `WITNESS_JOB_TAG_V1` (§7.1) → witness job | none | — |
| 2 | **Static gates** (§5.3) | chain reads | skip |
| 3 | Fetch the guest ELF (ProgramRegistry, today's path) and check its image id equals `programId` | ELF fetch | skip |
| 4 | Obtain the builder artifact: local cache → operator mirror → `hemi-code` (§13); verify its content id | artifact endpoint | per §16 |
| 5 | Run the builder in its sandbox (§10); `W` streams to the retention store | broker | per §16 |
| 6 | Execute the guest in the execute sandbox (§10.1) on `prefix ‖ W` at every po2 this host may prove at | none | per §16 |
| 7 | **Claim gate:** `J` ≤ 32,768 bytes; binding satisfied at every po2 with identical journals; fulfil DA size (§5.5); gas by the guide's formula; price ≥ reservation (§17.2); prove time leaves a margin before `D`, and each proof attempt fits the per-attempt proving timeout ((sized cycles at the slowest eligible card's benchmarked rate, else a floor for its kind, plus the card's measured Groth16 wrap, else an allowance for its kind — minutes on a CPU) × `deadline_safety_margin`, plus three times the measured execute); prove resources fit (host RAM for `W`, segment disk, VRAM, operator session cap — §15.3); the adapter's `SELECTOR()` matches this toolchain | chain reads | skip |
| 8 | Publish the bundle and its pin (§15) | none | skip |
| 9 | Revalidate the bundle against the host as it is now (§15.2); re-run the claimability `eth_call` (§5.3); send the lock transaction | chain | — |
| 10 | Prove the bundle: execute, compare, prove (§15.3) | none | the miner's own failure |
| 11 | Fulfil with `fulfillJobHashed`, under the DA nonce rule (§5.5) | chain | the miner's own failure |
| 12 | Delete the bundle per §15.2 | none | — |

A running simulation is aborted on `JobCancelled`, on `JobClaimed` by another prover, or on
`BidSubmitted`, and held while the router or Registry is paused or the adapter disabled.

### 5.3 Static gates (step 2)

- The envelope decodes strictly and every field is in range (§7.1).
- **Proof system:** the risc0 Groth16 adapter in Phase 1. Never `CUSTOM_VERIFIER` (its verifier is a
  submitter-controlled contract that can change behaviour after a lock, F5); never OpenVM (its
  32-byte journal cannot hold §7.2's layout and refuses the prefix marker).
- **Binding mode** served (§7.2): FULL, FIELDS, journal prefix (risc0); NONE only when assigned to
  this host's prover.
- **Submission form:** a direct `submitJob`, `submitJobSimple`, `submitJobBatch` or
  `submitJobDefault` transaction to the router — not inside the router's `multicall`, not through a
  contract (zkminer cannot rebuild those descriptors yet). The guest is registered in ProgramRegistry
  with fetchable URIs.
- **Deployment:** this host verified the deployment's core pins against `3bc441dd8` (§6).
- **Capabilities and limits:** the builder type is supported; every declared capability is
  provisioned *for this configuration* (chain id, method set, archive, served proof age, §11.1);
  limits are within host maxima (§7.1 says which are rejected and which clamped).
- **Claimable:** an `eth_call` of `claimJob(jobId, 0, 0)` from the staked prover at a mined block
  succeeds — that one read covers exclusivity, a live bid round, the release cooldown, the reopen
  limit, pauses, the adapter's state and stake — and the price it returns clears the reservation
  now, or, on a ramp, will by now plus the expected simulation time.
- **Admission** (§17) and **witness serving enabled with a passing self-test** (§10.3).
- **Right before the claim intent and again before the claim:** claiming is not paused and risc0 is
  not switched off; the signer is not jammed; the balance funds this claim and every held lock's
  fulfil; a card is free (inline jobs needing a card plus witness locks below the concurrency cap),
  taken in the same step as the check, so a claim in progress holds it. While risc0 is switched off,
  witness jobs are set aside.

### 5.4 Why the proven run equals the simulated run

A risc0 proof attests one execution of one ELF on one input. Between step 6 and step 10 these are
identical, and the bundle records each:

- **ELF:** retained bytes, content-addressed by image id (stripped and unstripped copies of one
  program share it).
- **Input:** the persisted `W`; the worker checks `sha256(prefix ‖ W)` against the bundle. The prefix
  is `abi.encode(jobId, job.prover)` — the staked prover, never an operator key.
- **Segment size:** a guest can observe its po2 (where segments suspend it, `sys_cycle_count`), so a
  journal is a function of po2; the miner proves only at a po2 it executed, or executes the new one
  first.
- **Randomness:** the `sys_rand` seed is zkminer's public rule (`SYS_RAND_RULE` `risc0-public-v3`,
  protocol 13), with no key: `SHA-256("zkminer/risc0/sys_rand/v3" ‖ image id ‖ sha256(prefix ‖ W))`.
  The miner derives it and passes it to the sandboxed execute; a prove worker derives the same from
  the input it reads. The bundle records the rule (`sys_rand_rule`, the SHA-256 of its domain). No
  proof binds the seed — a prover on other software can answer `sys_rand` with anything — so a
  journal that follows it depends on a prover-controlled input (§21.1). Nor does a journal that
  ignores it show anything: a guest that spot-checks `W` at an index it draws commits the same
  journal for an honest `W` under every seed, and a prover who picks the seed passes a forged one.
  So the execute counts the guest's `sys_rand` calls past the one its runtime makes before `main`
  (`WitnessExecutePo2::sys_rand_draws`, protocol 16), and the miner skips a job whose guest makes any
  (`GuestUsesSysRand`, §16). The count is of calls: a guest that reads its runtime's own draw from
  memory, or replaces risc0's runtime, is not caught by it (§8.2 forbids both all the same).
- **Other host inputs:** empty environment and arguments (the executor answers `getenv`/`argv` only
  from its own empty maps); the keccak po2 (`RISC0_KECCAK_PO2`, guest-visible through
  `keccak_permute`); the executor build of every worker that may prove the job.
- No clock, no host entropy, no I/O beyond the input.

Step 10's execute-compare-prove makes this a check rather than an assumption (§15.3).

**What "measure-matches-prove" covers.** zkminer's risc0 fork refuses at execution the known cases
where an execution succeeds and no proof verifies (seeded `sys_rand`, the bigint verifier, the halt
output digest, `sys_poseidon2`, undecodable encodings, traps, misaligned pointers and pc); the worker
adds exit-code, output-digest, assumption and keccak checks. Proving still runs paths an execution
does not (GPU kernels, segment memory, the keccak circuit, the Groth16 wrap), and those can fail: GPU
defects, resource limits, circuit rejections the fork does not yet catch. They are the same failures
inline jobs hit, a hostile guest can steer its workload toward them, and they are the miner's risk,
mitigated by step 7's resource gates and the worker's retries. SP1 needs its own argument (Phase 2).

### 5.5 What can still go wrong after a lock

**Nothing in the job.** On the contracts being deployed (§6) the journal binding is the only payout
gate for adapter jobs; callbacks are soft; adapters ignore `extraVerifierData`; a locked job cannot
be cancelled before its slash window; the fulfil never reads ProgramRegistry; the descriptor is
immutable. The builder and the sources are no longer consulted, and a witness lock takes its ELF,
descriptor, po2 set and journals from its bundle — program-wide marks (an image-id mismatch seen on
another job of the same program, an unsatisfiable-binding mark) never skip or release it, and the
reads it still needs (recovery, the chain) use reserved lanes that bypass per-caller throttles.

**Residuals,** none attributed on-chain:

- **DA throttle.** Hemi's sequencer leaves out any transaction whose estimated DA size
  (`GasPriceOracle.getL1GasUsed(tx) / 16`) exceeds the batcher's per-transaction cap — no cap below a
  3.2 MB unposted backlog, then 20,000 estimated bytes, falling to 150 at 12.8 MB — and every later
  nonce of its sender with it. So:
  - the claim gate keeps the exact fulfil (real journal, `callbackExtraData`, `extraVerifierData`,
    seal) under an operator cap, **default 2,048 estimated bytes**, configurable up to about 8,500
    (the lower no-stall equilibrium cap the deploy runbook derives); while the measured backlog
    (§13.5's reading) is above 2.5 MB, it uses the live per-transaction cap or skips;
  - a fulfil larger than the standard size (about 600 estimated bytes) is sent only as the sender's
    highest pending nonce; if it stays unmined while the head advances, or the safe-head lag passes
    600 s, it is replaced at its nonce by a minimal self-transfer so later nonces proceed, and re-sent
    when the throttle clears;
  - a batcher-stall fill eventually strands *any* fulfil, inline ones included; the guardian's router
    pause at a 2.75 MB backlog is what protects locks then.
- **Ordinary blockspace.** Anyone can buy blockspace past a deadline; priced by the tip ladder and
  step 7's deadline margin, exactly as for inline jobs.
- **Shared resources.** Prevented by construction: builder and artifact traffic never share a
  rate-limit domain or node with the miner's chain RPC (§11.1, §13.3); simulation runs in a
  low-priority cgroup (§10.2); the chain client serves held locks first (§17.6); retention has its
  own store and quota (§15.1).
- **Prover-side failures:** §5.4. Post-lock witness failures are recorded per caller and per device; a
  device with failures of one class from two or more callers takes no new witness lock; they never
  feed zkminer's host-wide stop on new programs (§16).
- **Governance.** Pauses and adapter disables have grace exits, but during a disable *anyone* may
  `graceRelease` a live lock (stake kept, job and work lost). A verifier swap becomes ready at the
  `readyAt` of `VerifierSwitchProposed` (48 h by default, governable from 1 h to 30 days); a proof for
  the old verifier can then only be released, so a held witness lock is proven and fulfilled before
  a pending swap's `readyAt`, or released when its proof cannot finish by then. It also watches the router's `UpgradeProposed` and takes no witness lock whose deadline
  falls after a pending upgrade's `readyAt`.
- **Operator faults:** a lost or unavailable retention store (§15.2); a downgrade below a
  witness-capable release while witness locks are held (an older build would prove the envelope
  bytes and release) — never do that.

### 5.6 Incentives and job shapes

Simulate-before-claim keeps the simulating miner safe; it is **not incentive-compatible on an open
job**. A lock transaction in Hemi's public, tip-ordered mempool announces that the job passed
simulation; any staked prover can copy it in the same block with a higher tip, at the same price,
risking only P(the job fails for it) × the release penalty (5% of collateral: 5 HEMI at the 100 HEMI
floor). On an open job a simulator that is copied wins nothing, and if copying wins, the market
slides back to claim-then-build.

What works, with no contract change:

1. **Exclusivity — the recommended Phase-1 job shape.** `assignedProver` plus an
   `exclusivityDuration` of at least the worst-case simulation time plus two blocks, on a bound job.
   Nobody else can lock inside the window, so the assigned miner simulates with P(win) = 1, and the
   job opens to everyone afterwards. Window jobs are taken with `claimJob` first, never with
   `claimAndFulfillAssigned`.
2. **Competitive bidding** (zkminer bids from Phase 2): a round of at least 300 s turns the race into
   a price competition; a copier's underbid binds it, and the first bidder can re-bid. Once a bid is
   live the caller cannot cancel, so later simulation is also free of the cancel hold-up.
3. **A Dutch ramp** deters *blind* claims (claim at `minPrice`, build later), not copies. Set
   `minPrice` near the requester's estimate of the lowest miner reservation, not near zero — a claim
   at `minPrice` that is released restarts the next prover's climb there (the guide's hold loops) —
   and a `rampUpPeriod` of two to three times the published worst-case simulation time. For a
   capability with a proof window (`maxProofAge`, §11.2), the ramp must reach the published
   reservation while the pinned block is still inside the window, minus simulation time.

zkminer classifies every lost race as *same-block* (its lock transaction was pending in the winner's
block) or *earlier*, keyed per caller; above an operator threshold of same-block losses it stops
simulating that caller's open jobs, but always serves exclusivity jobs. It sends open witness-job
locks through a private or sequencer-direct path when one is configured (§22).

Until a lock is mined, simulation work is exposed to the caller's free cancel and to
cancel-and-resubmit; that costs unpaid work, never stake. **Assigned NONE-bound jobs** may use
`claimAndFulfillAssigned` (one transaction) only when the miner trusts the caller, as the guide says:
the proof is public while the job is still Open.

### 5.7 Invariants

Enforced by the miner's runtime; no profile, scheme or builder may override them:

1. **Simulate before any lock path:** a persisted `W` whose execution at every po2 the miner may prove
   at yields identical journals satisfying the binding exactly as the router judges it, within every
   claim-gate limit (§5.2).
2. **Prove the published bundle, or release:** never re-run the builder or refetch after a lock;
   execute-compare-prove; a missing bundle on an available store is paged, waited for, optionally
   salvaged from operator-owned sources, then released (§15.2).
3. **Only governance adapters without submitter revert levers** (§5.3).
4. **All fetches through the broker:** typed, re-encoded requests; frozen exact method lists;
   broker-verified content; never the miner's chain-RPC provider account or key, never the same
   provider from the same egress IP, never the same node process (§11, §13, §14).
5. **Builder and guest execution run in the §10 sandbox,** with no keys, under a passing self-test.
6. **Bounded unpaid work:** the job's limits clamped by the host's, and admission (§17).
7. **The fulfil fits before the lock:** journal cap, DA size, gas, reservation, deadline margin.
8. **Witness locks are immune to program-wide marks and shared throttles** (§5.5).

## 6. What the contracts already guarantee

Verified against `hemiprove-contracts` at `3bc441dd8`. The live 743111 stack (zkmarket `c8333aa`)
has different core runtimes; witness jobs are served only on a deployment whose core pins match
`3bc441dd8`'s `ReleaseCorePins`.

- **F1. The journal binding is the only payout gate for adapter jobs** (`Types.sol` `JobDescriptor`;
  `HemiProveFulfill._checkBinding`, before any write or verifier call). FULL:
  `keccak256(abi.encode(JOURNAL_PREDICATE_DOMAIN_V1, proofSystemId, programId, publicValues))`.
  FIELDS: keccak of up to 8 pinned ranges in slot order, 7 when a marker occupies slot 0; a range
  past the journal is a mismatch, never a truncation. NONE: assigned jobs only. Markers: journal
  prefix `0xffffffff` (journal begins with `abi.encode(jobId, job.prover)`; FULL/FIELDS apply to
  `publicValues[64:]`, ranges ending within 32,704) and SP1 proof nonce `0xfffffffe`.
- **F2. `inputData` is opaque and immutable:** only `keccak256(inputData)` enters `descriptorHash`;
  `inputData + callbackExtraData + extraVerifierData ≤ 65,536` bytes at submit.
- **F3.** The journal cap, 32,768 bytes, is checked before the verifier.
- **F4. Callbacks are soft:** a reverting, zero-returning or codeless callback emits `CallbackFailed`
  and settlement proceeds; returndata copy is capped at 256 bytes; `callbackGasLimit` is fixed at
  submit (0 = 200k, else 50k–500k).
- **F5. `extraVerifierData`:** the risc0 and SP1 adapters ignore it; OpenVM's uses it, pinned by
  `programId`; for `CUSTOM_VERIFIER` jobs it names the submitter's own verifier contract.
- **F6.** A Locked job can be cancelled only once its slash window is open; once a bid is live the
  caller cannot cancel at all.
- **F7.** Fulfil never reads ProgramRegistry ("advisory only").
- **F8.** `fulfillJobHashed` fulfils without resending `inputData`.
- **F9.** The release penalty is snapshotted per job: 5% of `lockedCollateral` by default (1–30%
  governable); collateral is `max(ceil(price × bps), floor)`, `bps` default 150%, at most 500%.
- **F10.** Only `job.prover` can fulfil; operator keys can claim delegated but never fulfil.
- **F11.** `slashAndClaim` / `slashAndReopen` only after `D + G + TIMESTAMP_SLACK`; only governance
  moves a lock deadline; `MAX_REOPEN_COUNT` is 10.

**Consequence:** once a miner holds a published bundle whose journals satisfy the binding, no field
of the job can make the fulfil revert.

## 7. Job encoding

### 7.1 The witness-job envelope in `inputData`

```
inputData = WITNESS_JOB_TAG_V1 ‖ abi.encode(WitnessJobV1)            // abi.encode of the struct
WITNESS_JOB_TAG_V1 = keccak256("hemiprove.witness-job.v1")            // 32 bytes

struct WitnessJobV1 {
    uint8        builderType;    // 1 = WASM (Phase 1); 2 = RISC-V builder mode; 3 = declarative (Phase 2+)
    bytes32      builderId;      // sha256 of the artifact bytes (types 1, 3); risc0 image id (type 2)
    string[]     builderURIs;    // 0–4 transports, each ≤ 512 B: hemi-code (Phase 1); https, ipfs (Phase 2)
    bytes        builderParams;  // ≤ 16 KiB, passed verbatim to the builder; binds nothing
    Capability[] sources;        // 1–8 declared capabilities (§11)
    Limits       limits;
}
struct Capability { bytes32 class; bytes config; }   // class = keccak256("evm-rpc/v1"), …;
                                                     // config ≤ 1 KiB, decoded by the class schema
struct Limits {
    uint32 maxFetches;            // builder requests; a batch element counts as one
    uint64 maxFetchBytes;         // total response bytes delivered to the builder
    uint32 maxRequestBytes;       // per request, ≤ 65,536
    uint32 maxResponseBytes;      // per response
    uint64 maxBuilderFuel;        // wasmtime fuel (type 1)
    uint64 maxBuilderMemoryBytes; // linear memory
    uint32 maxBuilderSeconds;     // wall time from process start, including compilation
    uint64 maxWitnessBytes;       // |W|
    uint64 maxGuestCycles;        // see below
}
```

- **Encoding.** `abi.encode(job)` of the struct (Solidity `abi.encode(job)`, alloy
  `SolValue::abi_encode`), which begins with the `0x20` head-offset word. Decoding is strict: decode
  with validation, **re-encode, and require byte equality with `inputData[32:]`** (rejects trailing
  bytes, dirty high bits, non-canonical offsets, nonzero padding).
- **Ranges.** Unknown `builderType`, unknown capability class, a `config` that does not decode under
  its class schema, more than 4 `builderURIs` or one over 512 bytes, `maxRequestBytes` above 65,536,
  non-UTF-8 strings → the job is skipped. A zero limit means "none allowed", never "unlimited".
- **Unusable transports are ignored, not fatal:** an unknown scheme (the bytes before `://` matched
  exactly), a refused scheme (`http:`), a malformed entry of a known scheme, a `hemi-code` entry for
  another chain, or (in Phase 1) any `https`/`ipfs` entry. The job is skipped only if no source
  yields the artifact.
- **Host maxima:** `maxWitnessBytes` and `maxGuestCycles` above this host's maxima → reject (they
  decide retention and proving); the builder-side limits → clamp (a builder that needed more fails).
- **`maxGuestCycles`** is in the unit every prover computes the same way: the maximum, over the po2s
  the prover may use, of Σ over segments of 2^po2 plus 2^(keccak po2 + 3) per keccak request (2^20
  at the default keccak po2 17). `zkminer simulate` prints it per po2, and says at which po2s a job
  goes over it (§16).
- **Versioning.** Any change to the struct or a field's meaning is a new tag; a tag a miner does not
  know makes the job look inline, and it fails its binding in simulation, harmlessly. A new
  `builderURIs` scheme is not a new tag; a known scheme's format changes only under a new scheme
  name.
- **Size.** Keep the whole envelope under about 8 KB: the submit transaction is subject to the same
  DA throttle (§5.5), and above 20,000 estimated bytes it loses inclusion under any throttle.
- **The guest input is `W`** (after the prefix when the marker is set). Witness formats are a
  contract between builder and guest.
- **The tag** is 32 bytes, so an inline input starting with it is a 2^-256 accident, and
  misclassification cannot cause a bad lock: the claim gate judges the execution the miner actually
  performed.

### 7.2 The binding and the journal layout

The requester's guarantee comes **only** from the binding (F1) and what its guest proves. FIELDS
binds the bytes at the pinned offsets and nothing else — not the journal length, not its structure.
A witness that does not match the commitment either fails in-guest validation or yields a *valid*
journal carrying a different commitment, which only the binding rejects; so the pinned bytes must
sit at offsets no witness can move. Witness jobs use one layout:

```
[ abi.encode(jobId, prover)                64 bytes, journal-prefix jobs ]
  header: k words of 32 bytes, each big-endian, each written with env::commit_slice:
    schemeId
    commitment                                   // §8.1
    every question-defining parameter, or a digest of them (§8.2)
  outputs: free (length words of variable outputs go here, unpinned unless known at submit)
```

- **Write the header with `env::commit_slice` only.** (The reference guest assembles `prefix ‖
  header ‖ outputs` in memory and commits it with one `commit_slice` after the witness is consumed,
  so a failed check commits nothing.) Never `env::commit` (risc0 serde frames each value, writing
  128 bytes per 32-byte word) and never alloy `abi_encode()` of a struct with a dynamic member (its
  leading `0x20` head word shifts everything).
- **Pin the whole header.** With the prefix marker:
  `journalFields = bytes32((uint256(0xffffffff) << 224) | (uint256(H) << 192))` — slot 1 = (offset 0,
  length H), counted from journal byte 64, ending at most at 32,704. Without it:
  `journalFields = bytes32(uint256(H) << 224)`, ending at most at 32,768. `H = 32 × k`. zkminer's
  tools check it directly: `zkminer witness binding check` fails unless it can show `[0, H)` pinned
  (`H` from the `--word`s, `--header-bytes`, or, in `zkminer simulate`, a scheme-1 `W`'s `32 ×
  nWords`), and `simulate --adversarial`'s verdict is `fail` unless `[0, H)` is pinned and
  `expectedJournalHash ≠ 0`. A free header word is exploitable only together with a consistent
  change of `W` (another block and its header, another `k` and its proofs), which no mutation makes,
  so no attack on `W` can stand in for this check.
- **`expectedJournalHash = keccak256(header)`, computed from the requester's own parameters.**
  `zkminer simulate` confirms the bytes; it is never their source (a journal produced by the prover's
  choice cannot be the specification of the prover's choice).
- **The INTERACTION_GUIDE's binding cookbook applies in full:** the pinned ranges must determine the
  input uniquely (checked with a **mutation check** — change each parameter in turn and confirm the
  FIELDS hash changes); fixed-size data first; pin lengths and head offsets of variable data; know the
  serializer's framing; pin every word the consumer knows; never pin what you cannot predict.
- **Outputs and the DA cap.** The fulfil carries the whole journal; keep outputs small (commit a
  digest of large ones) so the fulfil stays under the DA cap of §5.5.
- **Determined-output jobs** may use FULL when the whole journal is known at submit; FIELDS with
  outputs free is the usual case. **Live-input jobs** (a signed feed) pin only the input-identifying
  header; a FULL hash on live input is unsatisfiable, is never locked, and stays Open until its
  caller cancels it.
- **The journal-prefix marker is the default for open risc0 witness jobs.** Without it a public proof
  of the same statement settles any sibling job, so a copier can settle duplicates without proving.
- **SP1 witness jobs are not served until Phase 2** (they need SP1's separate prefix buffer and the
  proof-nonce marker). **NONE** is allowed only with `assignedProver`: bilateral trust. zkminer's
  requester tools refuse a descriptor the router would refuse at submit (`_bindingMode`): NONE
  without an assigned prover, FIELDS ranges without a hash, a range past the journal room, a marker
  the proof system does not carry.

### 7.3 Interoperability and documentation deliverables

The envelope, the builder ABI and the class specs are off-chain conventions. A prover that does not
know them runs the guest on the envelope bytes, fails the binding in its own pre-claim check, and
skips the job. To let every prover serve witness jobs, the contracts repo publishes, as
documentation only:

- in `abi/INTERACTION_GUIDE.md`: the envelope (§7.1); `BuilderContextV1` and the builder ABI v1
  (§9.2); the class specs `evm-rpc/v1` and `blob/v1` (§11); the scheme-id table and the journal
  layout (§7.2, §8.1); the `hemi-code` locator, artifact manifest and the publisher's pacing and
  dedicated-key rules (§13); the ProgramRegistry Custom-URI convention for ELFs (Phase 2, §13.6); and
  the definition that `StorageURI.contentHash` and `elfHash` are keccak256 of the bytes the URI
  serves (for `hemi-code`, of the assembled artifact — never the manifest's sha256), or 0;
- in `IO_SCHEMA_INTEGRATION_GUIDE.md` ("Decoding Input Data"): `inputData` beginning with
  `WITNESS_JOB_TAG_V1` is a witness-job envelope, and a program's kind-1 input schema describes `W`,
  not `inputData`;
- in `DEPLOY_RUNBOOK.md` ("L2 liveness and the DA throttle"): `hemi-code` publishing is a legitimate
  bulk DA source; a DA-backlog page may come from an unpaced publisher (runs of ~23 KB
  `0x00`-prefixed contract creations from one sender).

## 8. Soundness for guest and prelude authors

The guest does not trust `W`; it re-validates `W` against values pinned in the binding before
computing anything. A stock zkVM guest cannot be used unchanged. What makes this tractable is a
**reference validation library per scheme** (audited `eth-block` state, receipt and transaction
modules, `content-merkle`, `signed-feed`) and **tooling that attacks the witness** (§21.1); hand-rolled
validation is where soundness bugs hide.

### 8.1 Schemes

| id | scheme | commitment | guest validates by |
|---|---|---|---|
| 0 | `inline` | (none) | — (today's inline jobs) |
| 1 | `eth-block` | `blockHash` | header hash + MPT / receipt / transaction tries (§8.4) |
| 2 | `content-hash` | `H(blob)` | re-hash the streamed blob |
| 3 | `content-merkle` | `H(tag ‖ root ‖ length ‖ leafCount ‖ …)` | streamed, injective Merkle root |
| 4 | `signed-feed` | `H(tag ‖ pubkey or signer set ‖ constraints)` | signature + constraints + uniqueness |

- **eth-block** — commitment = `blockHash` of block *N*. The guest strictly RLP-decodes the header
  (`stateRoot` is item 3) and checks its hash. For a state transition it also takes *N−1*'s header,
  checks `hash(parentHeader) == N.parentHash`, verifies pre-state proofs against
  `parentHeader.stateRoot`, executes, and **asserts the computed `stateRoot`, `receiptsRoot`,
  `logsBloom`, `gasUsed` (and `withdrawalsRoot` / `requestsHash` where the fork has them) equal
  the header's**. Storage and view statements (the §12 example) are scheme 1 too.
- **content-merkle** — the commitment binds the root, the byte length and the leaf count; the guest
  recomputes the root over the data it consumes, in order, with leaf indices from its own counter.
- **signed-feed** — the guest verifies signatures over a domain-separated payload (feed id, chain,
  purpose). `constraints` pin a freshness bound and an **exact round or epoch id** with a signer that
  signs one message per round; otherwise the prover chooses among valid messages. Quorums count
  **distinct signers** (strictly increasing indices into a pinned signer set and version, expired
  sets refused, low-s required), and the input set is fixed (every source's message for the pinned
  round, or a fixed subset), never a subset the prover picks. The guest commits the identifying
  fields of the messages it used.

### 8.2 Selection, completeness and host inputs

- **Every question-defining value is pinned or derived in the guest** by a rule fixed in the guest,
  from pinned values and authenticated data: the contract, the slots, the block, the log, the
  message, the count `k`. A value the builder found by an unproven query (an implementation address
  from `eth_getStorageAt`, a derived slot set, "the latest block") is a *hint*.
- **Selections over a collection need the whole collection.** "First", "largest", "all", "none"
  require rebuilding the full receipts or transactions trie from the complete list, or proving an
  on-chain enumeration (a length plus every element). Inclusion proofs prove existence only; mapping
  keys are not enumerable; `logsBloom` proves only absence (an unset bit).
- **No journal byte or selection depends on a host answer** other than authenticated parts of `W`:
  not `sys_rand` (nor std `HashMap`/`HashSet` with the default `RandomState`, `getrandom`, `rand` —
  use `BTreeMap` or fixed-seed hashers wherever iteration order can reach the journal), not
  `sys_cycle_count` (never bound work by cycles), not `getenv`/`argv`, not hint channels, not the
  segment size.
- **Failures abort.** A validation failure panics; a guest never commits a validity flag the binding
  leaves free. Under fused validation (§15.4) the final commitment check precedes every path to halt:
  nothing reachable with unauthenticated data calls `env::exit` or returns from `main` first.

### 8.3 Guards every prelude keeps

- **Scheme confusion.** The scheme id sits in a pinned header word, and every commitment this
  protocol defines carries a domain-separation tag (`H("hemiprove/content-merkle/v1" ‖ …)`). Where
  the commitment is an external hash (`blockHash`), separation rests on the pinned scheme id, or the
  guest implements exactly one scheme.
- **Field encoding.** Over BabyBear (risc0's Poseidon2) a 32-bit word `w` and `w + P` collide for
  every word, so an injective packing is mandatory: ≤ 30 bits per element (or 16-bit limbs), `10*`
  padding, total length and leaf count bound into the root. zkminer's executor refuses accelerated
  `sys_poseidon2`, so in-guest Poseidon2 is software-only; prefer accelerated SHA-256 for byte data.
- **Merkle malleability.** Distinct leaf/node prefixes, an explicit leaf count, no
  duplicate-last-node promotion (CVE-2012-2459); leaf indices from the guest's own counter. For
  external formats without leaf/node separation (Bitcoin's txid tree, CVE-2017-12842), refuse 64-byte
  transactions and check the proof depth against a coinbase proof from the same block.
- **Every read is authenticated.** Data read again (autoregressive decoding reuses every weight) is
  kept verified in guest memory or re-verified on each pass.
- **Fiat–Shamir, not `sys_rand`.** Challenges come from a transcript computed in the guest that has
  absorbed the pinned header **and every prover-supplied value the check covers** before squeezing.
  Each check needs error ≤ 2^-100 on its own (the prover can grind `W` offline): a BabyBear extension
  of degree ≥ 4, a field of ≥ 128 bits, or repetition. Spot-check sampling never proves an exact
  statement.
- **Proof composition.** Use `env::verify` (Halted(0)); the sub-proof's image id is a guest constant
  or pinned, never read from `W`; the sub-journal's input-identifying fields are checked against
  pinned or derived values exactly as a binding would.
- **Cross-job replay.** Without a marker the binding is to the statement; jobs that must not share
  proofs use the journal-prefix marker (§7.2).
- **The scheme id is advisory to the verifier.** Nothing on-chain checks that a guest implements the
  scheme it claims; trust rests on the guest being what it claims. Defenses: audited preludes;
  reproducible guest builds; an attestation binding a guest to its scheme(s) and prelude version,
  published off-chain alongside its ProgramRegistry `setBuildInfo` recipe (whose strings are emitted,
  not stored).
- **Preludes concentrate risk:** independent audit, signed releases, reproducible builds, version
  pinning; attestations record the linked version so an advisory can enumerate affected guests.
- **Wrong prelude:** each prelude asserts at entry that its scheme id and witness layout match the
  committed ones. The reference prelude reads nothing from a scheme-1 `W` unless it starts with
  `HPW` ‖ scheme 1 ‖ format version 1 and header word 0 is the scheme id 1; the statement then
  checks its own header word count.
- **Commit what you checked.** The reference library enforces it with types: a `Pinned<T>` built
  only from `W`'s header words and committed exactly once, in header order; an `Authenticated<T>`
  produced only by verifiers, from pinned values, from guest constants (`constant!`: an associated
  `const` of a sealed plain-data type, byte arrays, integers, `bool` or the prelude's own types), or
  by `fn`-pointer derivations of those; outputs only of the sealed `ToWord` types; trie keys taken
  only as `Authenticated` values; and a `finish()` that returns the journal only when every header
  word was committed and every item of `W` read. A `fn` pointer captures nothing but can still read
  a `static`, `thread_local!` or `Cell`: the guest lints refuse those in a guest's sources.

### 8.4 EVM state, receipts and transactions

A guest proving EVM facts:

- **Tries.** Strict RLP; every hash-referenced node checked by keccak (inline children only under 32
  bytes); exact hex-prefix path matching including leaf and extension remainders; paths computed by
  the guest — `keccak256(address)`, `keccak256(pad32(slot))`, `rlp(txIndex)` — from committed values,
  never from keys in `W`.
- **Accounts and storage.** The account leaf is `[nonce, balance, storageRoot, codeHash]`;
  `storageRoot` comes from the leaf, never from RPC JSON. Leaf values are RLP inside an RLP byte
  string: decode the value item, then strictly decode the inner RLP (≤ 32 bytes, no leading zeros,
  non-zero) and left-pad. **Absence** needs a verified exclusion proof: an absent account has nonce 0,
  balance 0, empty storage (root `0x56e81f17…b421`) and empty code, and an empty storage proof is
  accepted only under that root (RPCs return empty proofs with value 0 for absent accounts), and
  under it only the empty proof (a node's `["0x80"]` is normalised by the builder). State whether
  outputs use EXTCODEHASH semantics: 0 for an absent account and for one empty under EIP-161 (nonce
  0, balance 0, no code, whatever its storage; such an account can sit in the trie from a genesis
  allocation or a devnet's state edit), `keccak("")` for any other account without code.
- **Receipts and transactions** (the `sc.event` profile ships in Phase 1). Decode per EIP-2718:
  `type ‖ rlp(payload)` for types 0x01–0x04 and the OP Stack deposit type 0x7E (whose receipts add
  `depositNonce` from Regolith and `depositReceiptVersion` from Canyon), plain `rlp([...])` for
  legacy. Commit `(txIndex, logIndexInReceipt)`; a block-level log index needs every earlier receipt
  of the block. A log is linked to a sender or calldata only through a transaction-trie proof at the
  same index, with per-type signature recovery under the pinned chain id. The Phase-1 reference
  library proves and decodes receipts and transactions; per-type sender recovery is still to come,
  so a Phase-1 statement links a log to calldata or to a deposit's L1-set sender, not to a
  signature's sender.
- **Executed calls (`sc.call`, state transitions).** Abort on any state access the witness does not
  cover (never default a missing account or slot to empty); accept code only against the proven
  `codeHash`. Pin or fix as guest constants the **caller** (`from`, `tx.origin`), value (0), gas limit
  and gas price; commit success or revert and the return data. The EVM's hardfork rules, precompile
  set and EIP-7702 handling follow a fork schedule fixed in the guest, keyed by the pinned chain id
  and the authenticated header's number and timestamp (Base has P256VERIFY at 0x100 and 7702
  delegation; mainnet rules get both wrong). The block environment (number, timestamp, coinbase, gas
  limit, basefee, prevrandao, blob base fee) comes from the authenticated header; the chain id is a
  guest constant or pinned word; `BLOCKHASH` comes from an authenticated `parentHash` chain or
  proven EIP-2935 state.

Use audited verifiers for all of this. An incomplete or malformed witness then fails in the guest
during simulation (no lock), never as an unsound proof.

### 8.5 Anchors and canonicality

`blockHash` binds a header, not its inclusion in the canonical chain, and **nothing forward of a
trusted point can be checked from execution headers**: a child header carries no signature and, since
the merge, no proof of work, so "prove *N* descends from a checkpoint" is forgeable. Allowed anchors:

1. **Pin the target's `blockHash`.** Canonicality is the requester's job at submit. On OP Stack
   chains (Base, Hemi) take it from the node's `finalized` (at least `safe`) head, never the unsafe
   head, which can be reorged.
2. **Pin a later trusted hash and walk `parentHash` backward** in the guest: the target is proven to
   be an ancestor.
3. **Verify consensus in the guest:**
   - *Beacon:* the sync committee for the attested slot's period, advanced from the pinned one via
     proven `next_sync_committee` branches; ≥ 2/3 participation; a finality branch and an execution
     branch to `block_hash`. This trusts an honest 2/3 of 512 unslashable keys.
   - *Tendermint:* ≥ 2/3 of the set the header commits (adjacent) or more than the trust level of the
     pinned set (skipping); distinct validators; chain-id-bound sign bytes.
   - *Bitcoin:* a contiguous chain from a pinned checkpoint; each header's PoW checked against its
     own `bits` (decoded as Core's `SetCompact`: negative and overflow refused, target ≤ powLimit) and
     `bits` following the retarget rule. The anchor is the work accumulated **strictly after** the
     target, above a pinned threshold — total work since the checkpoint is not an anchor (real work
     up to the target's parent would count). Prefer anchor 1 from hVM's Bitcoin view.
   - *OP Stack via L1:* from a pinned or consensus-verified L1 header, prove a dispute game that is
     valid and finalized as `AnchorStateRegistry` defines it (resolved `DEFENDER_WINS`, past the
     finality delay, not blacklisted or retired, a respected game type; every field from L1 state),
     then the output-root preimage `keccak256(abi.encode(bytes32(0), stateRoot,
     messagePasserStorageRoot, blockHash))`, then walk `parentHash` back to the target. An unresolved
     proposal is not an anchor; an L2 block's own L1-origin fields are claims, not an anchor.
- The reference prelude implements anchors 1 and 2; anchor 3 is Phase 2.
- **Staleness.** Open jobs never expire, but committees rotate and validators unbond: pin the target
  height or slot, and cancel before the pinned set's trusting period or committee period ends.
- A consuming callback's canonicality check protects only the consumer's state, never the payment
  (callbacks are soft, F4); on Hemi a callback can see only hVM's Bitcoin view and the current L1
  origin. "The latest finalized block" is a live-input statement only with anchor 3.

### 8.6 Privacy

No input privacy against provers: every simulating miner sees `W`. Nothing in `builderParams`
(public calldata) is private; a salt there hides nothing, and a fetched salt is seen by every
simulating miner. Low-entropy committed inputs are brute-forceable from the public journal.
Commitments are *binding*, not *hiding*. Anything the builder receives can end up in the journal and
on-chain (§12.3).

### 8.7 Un-committable data

Data neither committable at submit time nor self-authenticating cannot be served trustlessly. With
its own authentication (a signature from a committed key, a notarized transcript, a value anchored to
a committed block) use `signed-feed` or a chain scheme; otherwise a proof attests only "I ran *M* over
*some* *X*". The protocol cannot tell such jobs apart (the binding simply pins nothing
input-identifying); they are not presented as trustless, and miners can still serve them. The same
holds inside one witness: data the guest cannot authenticate is only as good as the prover's choice.

## 9. The witness builder

### 9.1 Types and the WASM profile

| Type | Runtime | `builderId` | Phase |
|---|---|---|---|
| 1 | WASM module, wasmtime, no WASI | sha256 of the module bytes | 1 |
| 2 | RISC-V program in the risc0 executor's **builder mode** | risc0 image id; the executor version is part of the type | 2+ |
| 3 | Declarative manifest (fetch-and-place, no code) | sha256 of the manifest bytes | 2+, needs its own spec |

**Why WASM first.** wasmtime is built to run hostile code; the risc0 executor is not, as shipped: it
registers a fixed table of default syscalls (argv, getenv, log, pipe, keccak, verify, read, write)
that cannot be removed; loads a guest-chosen request length into host memory before a handler runs;
keeps pipes as unbounded host-memory queues; is quadratic in host CPU on `verify_integrity2`; sends
fd 1/2 to the process's stdout/stderr; can panic `LocalProver::execute` on a malformed header; meters
user cycles only; and truncates a user syscall's reply to 1 KiB. Type 2 waits for a fork patch adding
a builder mode (stdin reads, a capped witness fd, a capped panic, a chunked fetch channel, everything
else an error, request lengths capped before loading, randomness seeded from a public constant or
fresh OS randomness).

**The WASM profile (ABI v1 freezes it).**

- **Features:** MVP, mutable globals, sign-extension, saturating float-to-int, bulk memory,
  multi-value, and reference types for funcref only (overlong `call_indirect`, which current Rust
  emits). Everything else off: SIMD (fixed and relaxed), threads and atomics, multi-memory, memory64,
  exceptions, tail calls, GC, extended-const, the component model. Module API only.
- **Build:** `wasmtime` pinned to an exact LTS release (`=X.Y.Z`), `default-features = false`, features
  `runtime` and `cranelift` only.
- **Config:** fuel and epoch interruption on, both armed *before* instantiation (start functions run
  then); on-demand allocator; default guard regions; Spectre mitigations on; `max_wasm_stack` ≤ 1 MiB
  on a thread with ≥ 8 MiB of stack; `wasm_backtrace(false)`; NaN canonicalization on;
  `parallel_compilation(false)`; no coredumps.
- **Store limits:** one memory, one table, one instance; table elements ≤ 65,536; memory ≤ the
  clamped `maxBuilderMemoryBytes`.
- **Pre-pass:** a streaming wasmparser pass rejects, before compilation, function bodies > 256 KiB,
  > 4,096 locals, > 100,000 functions, `br_table` > 65,520 targets (wasmtime's own limit), more than
  one memory or table, initial memory above the clamp, and oversized data or element segments.
- **Compile-cost budget.** Those structural limits do not bound compile time: compilation runs before
  any fuel is consumed, and Cranelift's cost grows with control nesting × locals², nesting depth²,
  branch joins × locals, declared locals and function-type arity² (trampolines). A 262 KB module of
  nested loops over 4,096 locals passes the limits above and compiles for more than 300 s past
  9 GiB. The pre-pass therefore also bounds control nesting depth per function, declared locals per
  module, params + results per type, and module-wide sums of those cost terms, calibrated so every
  known bomb class is refused or compiles in seconds while real Rust builders keep at least 10×
  headroom (the caps and their calibration live with the pre-pass). The wall clock (counted from
  process start, with the watchdog started before compilation) and `memory.max` remain the backstop.
- **Compilation** happens inside the builder's sandbox, single-threaded, under its cgroup and a wall
  clock that starts at process start, at `OptLevel::None` (or a baseline compiler or interpreter
  chosen by measurement). **No compiled-code cache in Phase 1** (`Module::deserialize` trusts its
  bytes as native code; a writable cache would be code execution in every later builder).
- **Hard ceilings in code,** whatever the configuration: builder memory ≤ 1 GiB, wall time ≤ 300 s,
  `W` ≤ 1 GiB (`[witness] max_witness_bytes`, default 32 MiB, §15.4, can be raised only up to it).
- **Host functions** check `len` against the per-call cap before touching guest memory, use checked
  u32 arithmetic, trap on out-of-bounds pointers, and charge fuel per byte copied plus a fixed charge
  per call (a larger one per `fetch`, which costs an IPC round trip); once a fetch has returned status
  3, every later fetch answers 3 locally without IPC. (wasmtime charges bulk-memory operators
  `memory.copy`/`fill`/`init` one fuel per byte, so they are not a fuel bypass; CPU is still priced by
  `maxBuilderSeconds`.)
- The builder SDK pins a matching explicit `target-feature` list.

### 9.2 Builder ABI v1 (type 1)

The module imports only from `hemiprove_builder_v1` and must export one 32-bit `memory` and
`run() -> i32` (other exports, such as the `__heap_base`/`__data_end` globals Rust emits, are ignored
and never called). **An import not listed here fails instantiation, a permanent verdict.** ABI v2 is a
new module name.

```
struct BuilderContextV1 {        // the input, as abi.encode(ctx) with its 0x20 head word
    uint64       hemiChainId;
    address      router;
    bytes32      programId;
    bytes32      proofSystemId;
    bytes32      expectedJournalHash;
    bytes32      journalFields;
    Capability[] sources;        // as in the envelope
    Limits       limits;         // the envelope's declared values, never the host's clamps
    bytes        builderParams;
}
```

| Import | Semantics |
|---|---|
| `input_len() -> i32` | length of the encoded context |
| `input_read(offset: i32, ptr: i32, len: i32) -> i32` | copies up to `len` bytes from `offset`; returns the count (0 past the end) |
| `fetch(cap: i32, req_ptr: i32, req_len: i32) -> i64` | bits 63–56: status (0 ok, 1 denied, 2 failed, 3 exhausted); bits 55–32: zero; bits 31–0: response length. Replaces any previously held response. Blocks; fuel does not advance while it waits |
| `response_read(offset: i32, ptr: i32, len: i32) -> i32` | copies from the held response; returns the count |
| `witness_write(ptr: i32, len: i32) -> i32` | appends to `W`; 0 ok, 1 over `maxWitnessBytes` (the run then fails) |
| `log(ptr: i32, len: i32)` | to a sanitized diagnostic sink; 64 KiB per job in total, the rest dropped |

- There is **no `jobId` and no prover address** in the context: the miner adds the prefix itself,
  and their absence denies a requester any link between a staked prover and a simulating host.
- `limits` carries the envelope's declared values, so the context does not fingerprint the host's
  configuration.
- **Termination:** success only when `run` returns 0; a trap, fuel or memory exhaustion, or the wall
  clock → failure; the run is *transient* only if the broker reports an **operator-side** failure
  (transport, timeout, a non-2xx answer other than 404, operator budget or spool exhaustion, a lane
  wait; a connect timeout is the operator's, a timeout after the request was sent is the request's own;
  a 404 from a JSON-RPC endpoint is the operator's, a 404 or 410 from a blob mirror is unanswerable),
  or the wall clock expired while a fetch waited on the operator side. A request every endpoint
  answers as lagging or not found is *unanswerable*, which is the builder's question, not the operator's
  failure: a builder must not be able to buy a free retry by asking for a future block or an unknown
  hash (§16) — once **two independent endpoints** (distinct host and port) for that chain answered so,
  or the block lies deeper below the head than the source's **pruning horizon** (unbounded when an
  endpoint serving it is `archive`, else the largest `max_proof_age` of its endpoints, at least 128
  blocks of recent state). With fewer, a node behind the chain answers a valid request exactly so (a
  block it does not know yet, state it lacks at a recent block), so the run is *source-lagging*: retried
  with backoff and never counted against the caller (§16). The price is a few retries a builder can
  cause on a host with one endpoint per chain; a host with two independent endpoints per chain gives it
  none. The runner writes a marker on its summary pipe once compilation succeeds and before
  instantiation; a runner error reported after that marker is treated as a builder trap, since a
  builder that escaped wasmtime controls the runner process and could otherwise fake an internal
  error for a free retry.
- **Nothing else:** no clock, no randomness, no file system. Placed segments (`witness_place`,
  §15.4) belong to ABI v2.

### 9.3 What the builder is not required to be

- **Deterministic:** the miner proves the `W` it persisted.
- **Correct:** a wrong `W` fails in-guest validation (or answers a question the binding does not pin,
  which is the requester's binding to fix, §8.2).
- **Fast:** it only has to finish within its limits.

## 10. Sandbox, processes and privileges

### 10.1 Process topology

| Process | Holds | Network | Talks to |
|---|---|---|---|
| **Miner** (today's) | signing keys, the chain client, the lock journal | `chain.rpc_url` | spawns everything below; persists `W` from the builder's pipe into the retention store; writes bundles and verdicts |
| **Broker** (one per host) | provider keys (by file or fd, never env or argv); the endpoint file | none of its own: every TCP connection is made by the miner's connector and handed over connected (`SCM_RIGHTS`, §14.2) | builders over per-job sockets; the miner (control fd, connector fd); endpoints and the artifact endpoint (`hemi-code` reads) only over sockets the connector made |
| **Builder runner** (one per job) | nothing | none (an empty network namespace) | its socket to the broker; a write-only pipe for `W` to the miner |
| **Execute worker** (one per job) | the seed for this (image, input), by the public rule | none | reads `W` from the retention store through a read-only fd; returns journals, cycles, exit codes, segment bytes |
| **Measure and prove workers** (today's, GPU) and `sp1-gpu-server` | nothing secret (a witness job's seed is the public rule's, derived from the input it reads) | none: confined before their first guest (§10.3) | the miner over their command pipes; a proving SP1 worker also its own server over one Unix connection; read `W` from the retention store |

- Job identity at the broker is **the per-job socket it was handed**, not `SO_PEERCRED` (which, on a
  socketpair, reports whoever created the pair).
- `W` streams in ≤ 1 MiB chunks to the miner, which writes it to the retention store and counts it
  against `maxWitnessBytes`; nothing buffers it whole.
- `zkminer simulate` uses the same launcher; there is no in-process builder path.

### 10.2 The sandbox contract

Each property has a mechanism; none is assumed.

| Property | Builder runner and execute worker | Broker |
|---|---|---|
| Resource caps from the first instruction | `clone3(CLONE_INTO_CGROUP)` into a cgroup the miner pre-creates and owns: `memory.max` (charged against the dispatcher's host-RAM reservation), `memory.swap.max=0`, `pids.max`, `cpu.max`, low `cpu.weight`, a cpuset excluding the cores that feed provers | its own cgroup with a memory cap and a global in-flight byte budget |
| Killable | the miner writes `cgroup.kill` (a uid-switched child cannot be signalled by the miner) | systemd unit / supervisor |
| Isolation | new user, mount, pid, network (empty) and ipc namespaces; a subordinate uid (newuidmap) or a systemd `DynamicUser=`; private `/tmp` and `/dev/shm`; a minimal `/dev` with no GPU nodes; no `/home`; an empty Landlock ruleset | its own uid (not the miner's, not a builder's); private `/tmp`; no access to `~/.zkminer`; no sockets of its own (Landlock grants no TCP port) |
| No new privileges, no leaks | `NO_NEW_PRIVS`; `PR_SET_PDEATHSIG` set *after* the credential change, then `getppid()` re-checked; `close_range(3, ~0)` keeping only its socket/pipe; `RLIMIT_CORE=0`; no capabilities (effective, permitted, inheritable and ambient sets cleared, whoever started the miner) | `PR_SET_DUMPABLE(0)`; `RLIMIT_CORE=0`; no capabilities (likewise) |
| Syscalls | seccomp: no `socket`, `connect`, `open*`, `execve`, `ptrace`, `process_vm_*`; no `setsockopt` but `SO_RCVTIMEO`/`SO_SNDTIMEO`; read/write only on its own fds | seccomp: no `socket`, `connect`, `bind`, `listen`, `accept*`; no `setsockopt` but `IPPROTO_TCP`/`TCP_NODELAY`; `socketpair(AF_UNIX, SOCK_STREAM)` only until its runtime has started, then sealed |

- The miner and `artifact publish` also call `PR_SET_DUMPABLE(0)` and set `RLIMIT_CORE=0`, and
  overwrite secret environment bytes in place before `remove_var` (`/proc/<pid>/environ` serves the
  initial block).
- Filesystem (path) Unix sockets are filesystem objects any network namespace can reach; host
  sockets such as the SP1 server's `/tmp/...sock` are protected by the private `/tmp`, the mount
  namespace and Landlock, not by the network namespace. The measure and prove workers cannot make or
  reach a socket of any kind once confined (§10.3).
- A socket the connector hands over is connected by the miner, and no sandbox can point it anywhere
  else: no `connect` (no `AF_UNSPEC` disconnect and reconnect); TCP Fast Open to another address
  fails on a connected socket; no socket option re-routes it (IPv6 routing headers, IPv4 source
  routes, `SO_BINDTODEVICE`/`SO_BINDTOIFINDEX`, `IP_UNICAST_IF`/`IPV6_UNICAST_IF`, `IPV6_NEXTHOP`,
  `IP_TRANSPARENT`, `SO_MARK` and the TTLs all fail with `EPERM`); TCP ignores `IPPROTO_IP` and
  `IPPROTO_IPV6` ancillary data on `sendmsg`; and the one `SOL_SOCKET` message that selects a route
  (`SO_MARK`) needs `CAP_NET_ADMIN`, which no sandbox holds.

### 10.3 Deployment modes and the self-test

- **System install (recommended):** a one-time privileged setup, printed by `zkminer witness setup`:
  systemd units for the broker (own user, network namespace, nftables ruleset) and a delegated cgroup
  subtree (`Delegate=yes`) under which the miner creates per-job sandboxes with `DynamicUser=` or
  subordinate uids.
- **Rootless:** where unprivileged user namespaces are unavailable (Ubuntu's AppArmor restriction
  `kernel.apparmor_restrict_unprivileged_userns = 1`, no sudo), the builder runner and execute worker
  run under the miner's uid with: a Landlock ruleset (ABI ≥ 6) that grants no filesystem access, no
  TCP bind or connect, and scopes signals and abstract Unix sockets; seccomp (no `socket`, `connect`,
  `open*`, `execve`, `ptrace`, `process_vm_*`, no `setsockopt` but the socket timeouts, no SysV IPC —
  shared memory there would outlive the
  cgroup and reach the miner's segments — and no metadata writes through inherited fds: `fchmod`,
  `fchown`, `f*xattr`, `flock`, leases, `chattr` ioctls, `file_setattr`); a cgroup in the user's delegated cgroup v2 subtree
  (`memory.max`, `memory.swap.max=0`, `pids.max`, `cpu.max`, `cpu.weight`; killed with
  `cgroup.kill`); `NO_NEW_PRIVS`; `PR_SET_DUMPABLE(0)`; `RLIMIT_CORE=0`; no capabilities. Landlock denies `/proc`,
  `~/.zkminer`, `/tmp`, `/dev/shm` and GPU nodes by path, and Yama keeps the miner un-traceable. The
  broker has no network in either mode: it names an operator endpoint by index over a socket to the
  miner's connector, which loads the broker file itself, resolves, admits each address with
  netguard's floor over the miner's facts and deny CIDRs (including a per-destination kernel route
  query), connects, and returns the connected socket. A broker that breaks the protocol, leaves its
  answers unread, or closes its connector socket without exiting is cut off and killed, together
  with the builder runners registered with it (§14.2). The sandbox launcher
  clears the child's environment and joins it to its job cgroup before `exec`, and the miner's
  delegated cgroup must belong to a unit with `Delegate=yes`, which is checked through systemd. Rootless mode is an explicit operator opt-in (`[witness] sandbox_mode = "rootless"`) that
  acknowledges the missing kernel floor for the miner's own connections (the connector's in-app
  floor is the only one).
- **Measure and prove workers,** in both modes. Their GPU stack (device nodes, ioctls, many
  threads, helper processes) rules out the builder's profile, so the workers that run requester
  guests confine themselves instead, on the assumption that a guest can escape its executor: before
  the first command that runs a guest or uses the GPU, for the rest of the process's life, on every
  thread at once (seccomp and Landlock `TSYNC`), inherited by everything they start.
  - seccomp: no socket of any kind, Unix ones included, and no `connect`, `bind`, `listen` or
    `accept*`. A CUDA worker initialises the driver first. The SP1 worker may still make Unix
    stream and seqpacket pairs, never datagram ones, and a proving one keeps only its connection to
    its own server. Also no `io_uring`, `bpf`, `ptrace`, `process_vm_*`, `pidfd_getfd`, keyrings,
    `mknod` or `TIOCSTI`. No namespaces and no mounts: `unshare`, `setns`, `clone` with any
    `CLONE_NEW*` flag, `mount`, `umount2`, `pivot_root`, `chroot` and the new mount API (`fsopen`,
    `fsconfig`, `fsmount`, `fspick`, `move_mount`, `open_tree`, `open_tree_attr`, `mount_setattr`)
    are refused, and `clone3` fails with `ENOSYS` so libc falls back to `clone`, whose flags the
    filter reads. Also no `userfaultfd`, `perf_event_open`, `name_to_handle_at` or
    `open_by_handle_at`. No metadata writes, by path or through an fd: `chmod`, `fchmodat`,
    `fchmodat2`, `fchmod`, `chown`, `lchown`, `fchownat`, `fchown`, the `*setxattr`/`*removexattr`
    family (with `setxattrat`, `removexattrat`), `utime`, `utimes`, `futimesat`, `utimensat` and
    `file_setattr` (Landlock has no right for metadata, and the workers run as the miner's uid),
    and their ioctl forms (`FS_IOC_SETFLAGS`, `FS_IOC_FSSETXATTR`, `FS_IOC_SETVERSION`, their
    32-bit twins, `FS_IOC_ENABLE_VERITY`). No leaving the session or process group (`setsid`,
    `setpgid`), and nothing done to another process's limits or scheduling: `prlimit64` that sets
    another pid's limit, `setpriority`/`ioprio_set` other than on the process itself, and
    `sched_setaffinity`, `sched_setscheduler`, `sched_setparam`, `sched_setattr` other than on pid 0
    (the ROCm worker and SP1's HIP server keep `sched_setaffinity` of any thread: ROCm starts its
    threads with a CPU set, which glibc applies by thread id). SP1's executor runner, which the SDK
    would unpack into the private `TMPDIR` and `chmod`, is written there by the worker (found by
    hash in its own executable), mode 0755, before it confines itself, running nothing doing so;
    the server's mode changes go to its supervisor, which sets 0755 itself only on a regular, single-link, user-owned file with SP1's runner name in that
    directory, opened without following links, deciding on the call's registers alone; every other
    mode change is refused. The same filter confines `sp1-gpu-server` and its supervisor.
  - Landlock:
    - read: the system's files, its own `/proc/self` and the few global `/proc` files runtimes
      read (`cpuinfo`, `meminfo`, `stat`, `uptime`, `loadavg`, `version`, `devices`, `driver`,
      `sys/vm/mmap_min_addr`, `sys/vm/overcommit_memory`; the SP1 worker and server all of `/proc`,
      since the executor's memory monitor reads its runner child's entries), the worker's own
      directory and SDK files, and the retention store;
    - write: a private `TMPDIR`, the segment directories (a witness proof's slot directory; for the
      risc0 worker's other proofs, its own `~/.zkminer/risc0-segments/<pid>`), the GPU kernel caches,
      and, for an SP1 server, the user's Groth16 queue (`~/.zkminer/locks`, never in `/dev/shm`);
    - execute: only the loader and what the worker starts;
    - devices: the GPU nodes;
    - scoped signals (`kill`, `tgkill`, `rt_sigqueueinfo`, `rt_tgsigqueueinfo` and
      `pidfd_send_signal` alike) and abstract Unix sockets.

    `~/.zkminer` (but a risc0 worker's own segment directory there), `~/.ssh`, `~/.config` and the
    rest of the home directory are out of reach, and so are the miner's and other workers' `/proc`
    entries (for SP1, their memory and environment).
    Links, renames, removals, new directories
    and symlinks, and truncation outside the writable paths are refused (the probes check each).
  - `sp1-gpu-server` runs every SP1 proof's guest, so it is confined from its first instruction. It
    is started through a shim under a supervisor that grants its own listener (`socket`, `bind`,
    `listen`, up to its first `accept`) and nothing after. It never gets `connect`.
  - No network filesystem within reach. Landlock governs what is opened, not the path walk: a
    `stat`, `access`, `readlink`, `getxattr`, `statfs`, or the lookup of an `open` it then refuses,
    reaches any directory — on a network filesystem a request to its server carrying a name the
    guest chose, on FUSE a request to a user-space daemon, on an automount map a mount of whatever
    the name says. So a worker confines itself, and runs a guest, only if every mount of its mount
    table that a path can reach (a mount hidden under another is left out) has a type known to be
    local (disk, memory and kernel filesystems; unknown types refused), every granted path is on a
    local filesystem by `statfs`, and its working directory and open files are on local
    filesystems. Exceptions: another user's FUSE mount without `allow_other` (the kernel keeps the
    process out; confirmed with a `statx`); a direct automount point whose target is local
    (triggered once if idle); and two FUSE filesystems only root can mount: `lxcfs` and `fuseblk`
    (ntfs-3g, exfat-fuse) on a block device. A user's own FUSE mount is refused whatever its type
    or source says (an unprivileged FUSE program picks both): gvfs, the document portal, squashfuse
    and AppImage mounts included, so on a desktop session the miner runs as a user of its own. Every
    remote-capable FUSE filesystem (sshfs, rclone, s3fs, davfs, smbnetfs, curlftpfs, gocryptfs,
    encfs), 9p and virtiofs (VM host shares) and indirect automount maps are refused. The check runs
    before the confinement, again after, and again before every later guest command; the server's
    supervisor checks before it starts the server and the server again before its `exec`; the
    builder runner, the execute worker and the broker check before their sandbox is applied. The
    mount table is watched (`POLLPRI` on `/proc/self/mountinfo`): a change that leaves something
    within reach that is not local ends the worker (exit 78), the server (its supervisor kills it)
    and, from the miner, every worker. The error names each mount, its type and source.
  - A CPU host's Docker Groth16 step runs in a helper started before the confinement. It never runs
    a guest and trusts nothing the worker sends: the worker converts its `identity_p254` seal into
    the prover's input itself, and the helper accepts only that input's exact shape (the fixed JSON
    text, one canonical decimal per seal element, each below BabyBear's or BN254's scalar-field
    modulus by position, at most 1 MiB), writes the prover's input from the numbers it checked, and
    answers a panic with an error and keeps serving. The image is pinned by digest and runs with
    `--network none`. It works below the temporary directory the worker was started with, outside
    every path a confined process may write; the container sees its input read-only and may write
    only the proof file, which the helper reads as a regular file without following a link.
  - Ending: each worker runs in a cgroup of its own — below the miner's delegated cgroup (joined
    before `exec`, memory ceiling as `memory.max`), else a scope of the user's systemd manager that
    holds it before it is sent anything — and every end of a worker writes its `cgroup.kill`. A
    reaper (`/bin/sh` in its own session, on a pipe only the miner writes) kills every worker's
    cgroup and process group when the miner dies, however abruptly; no worker starts without it. A
    thread of the miner watches the mount table and kills every worker when a mount within their
    reach is not local. Without either cgroup a worker and what it starts end by process group.
  - Every part is checked after the fact: the filter is on every thread, no disallowed socket is
    open, `unshare` is refused and `clone3` unimplemented, `/` is unreadable, the parent is
    unreachable by signal, and no filesystem within reach is non-local. A worker whose confinement
    fails, or whose kernel lacks Landlock ABI 6 (ABI 8 for a multithreaded worker), refuses to run
    guests.
  - Accepted residue: the GPU kernel drivers (a driver bug is outside this model); what a guest
    can read, which it can publish in its journal: system files, other processes' `/proc` status,
    and the retention store; the moment between a network or FUSE mount and the kill of every
    worker (the kernel's notification, then microseconds); SP1's executor shares a proof's guest memory
    and trace ring with its runner through memfds, which no confined process can open but an
    unconfined process of the same uid (the miner, a worker before it confines itself, `rocm-smi`)
    can, through `/proc/<pid>/fd`, so SP1 runs under a user that runs nothing else; memory allocated
    through such a descriptor is bounded by the worker's cgroup and the host's RAM, not by
    `/dev/shm`, and the runner's memory limit does not see pages written through it and never
    mapped; a confined SP1 server can hold the user's Groth16 queue slots (`~/.zkminer/locks`, mode
    0700) and so delay the others' final wraps; no confined SP1 process can open, create or remove
    anything in `/dev/shm` (it can list the names there); hosts with neither a delegated cgroup nor a
    systemd user manager end workers by process group; and storage remote underneath a local filesystem type (iSCSI, NBD
    or RBD block devices, a loop file on NFS, an overlay layer outside the mount table).
- **Self-test,** at startup and hourly, from inside each sandbox: reading `~/.zkminer/config.toml`
  fails; opening `/dev/nvidiactl` fails; `socket()` fails in the builder; inside the broker, `socket(AF_INET/AF_INET6)` fails and
  `connect`, `bind`, `listen` and `accept4` fail, and the connector refuses an index past the
  configuration; every re-routing socket option (`IPV6_RTHDR`, `IPV6_2292RTHDR`, `IP_OPTIONS`,
  `SO_BINDTODEVICE`, `SO_BINDTOIFINDEX`, `IP_UNICAST_IF`, `IPV6_UNICAST_IF`, `IPV6_NEXTHOP`,
  `IP_TRANSPARENT`, `SO_MARK`, the TTLs) fails inside the broker on fd -1 and on a socket the
  connector hands it for its first endpoint, while `TCP_NODELAY` works; in the runner and worker
  sandboxes every option but the timeouts fails; every sandbox reads back no capability; no sandbox
  starts while a network or FUSE filesystem or an automount map is within reach; in the
  miner, the connector refuses an address outside every role entry, a private
  address (public mode) and a malformed request; `/proc/self/status` shows `Seccomp: 2` and `NoNewPrivs: 1`; the cgroup limits
  apply. Each run is bounded (120 s; one that does not finish fails) and serving starts in the
  background. Any failure disables witness serving (`PAGE: WITNESS-DISABLED`); inline jobs are unaffected.
  Never run with a weaker sandbox.
- **`[witness] enabled` defaults to false.** Enabling it requires a passing self-test, a persistent
  quota'd retention store (§15.1), at least one provisioned capability, and an unexpired
  `HEMI_PER_ETH` (§17.2).

### 10.4 Supply chain

Every miner runs every admitted builder, so one wasmtime n-day is network-wide code execution inside
builder sandboxes for the cost of one job. Pin wasmtime on an LTS line; gate wasmtime, cranelift and
wasmparser with a `cargo deny` RustSec check and a patch service-level target; keep the runtime kill
switch (`[witness] enabled`); offer `[witness] builders = "any" | "attested"` (attested = builder ids
signed in the builder registry, Appendix A); record the wasmtime version in every verdict; build the
SDK reproducibly.

## 11. Data sources and the broker

### 11.1 Capabilities and provisioning

The envelope declares capabilities, never URLs. A class is provisioned only if its spec (config
schema, request format, frozen exact method list, parameter caps, cost weights) is published, and
only *for a configuration*: chain id, archive, served proof age, method sets.

- **Tier 1 (default):** operator-bound endpoints — the operator's own nodes, or providers under its
  own account. Keyless public endpoints of unknown operators are not bindable: whoever runs them sees
  the builder's queries.
- **Separation from the miner's chain RPC:** a builder or artifact endpoint never uses the same
  provider account or key as `chain.rpc_url`, never the same provider from the same egress IP, and
  never the same node process, database or host. zkminer refuses an endpoint whose host equals
  `chain.rpc_url`'s: the broker file's `chain_rpc_host` names that host, the broker refuses every
  endpoint on it, and the miner refuses to start a broker whose file names another host (developer
  mode only warns: a local test network runs its chain and endpoints on one host). Different
  providers may share the host's IP. If the miner's own Hemi node is its
  only Hemi node, a Hemi-chain class is not provisioned.
- **Operator nodes reachable by the broker** must have globally routable addresses (a node on
  loopback or the LAN is usable only in dev mode, §14) and expose only `eth`, `net` and `web3`, with
  `--rpc.gascap`, `--rpc.evmtimeout`, `--rpc.batch-request-limit` and `--rpc.batch-response-max-size`
  set, and no unlocked accounts.
- **Tier 2** (requester-located URLs) is Phase 3 and off by default.
- **`builderParams` select, never introduce:** a fetch names a `cap` index from the envelope; params
  never add an endpoint, URL, method set or budget.
- **Canonicalizing responses is not needed:** each miner proves its own persisted `W`, and the guest
  re-checks everything.

### 11.2 `evm-rpc/v1`

- **Config:** `abi.encode(uint64 chainId, bool archive, bytes32 methodSet, uint64 maxProofAge)`, where
  `maxProofAge` is the deepest `head − block` at which the job needs `eth_getProof`. A host provisions
  the configuration only if its endpoint serves proofs at least that deep (many nodes serve them only
  near the tip; `archive` does not imply it).
- **Request** (the bytes a builder passes to `fetch`): one JSON-RPC 2.0 object or a batch array of at
  most 32, each exactly `{"jsonrpc":"2.0","id":…,"method":…,"params":[…]}`. Keys are exact and
  case-sensitive; unknown, duplicate or case-variant keys, non-canonical numbers and non-hex data are
  rejected. Block parameters may be a number, `latest`, `safe` or `finalized` (resolved by the broker
  to a number) or an EIP-1898 object `{"blockHash":"0x…"}` / `{"blockNumber":"0x…"}`; `pending` and
  `earliest` are rejected.
- **The broker builds the outgoing request itself** — its own ids and batch framing, params
  re-encoded from the parsed form — so a parser difference between broker and node can never smuggle
  a method (geth's Go `encoding/json` matches keys case-insensitively, last match winning, so a
  forwarded `{"method":"eth_chainId","Method":"debug_setHead"}` would run the second).
- **Response** (the bytes `response_read` returns): canonical JSON, re-emitted by a streaming
  tokenizer without building a value tree: `{"jsonrpc":"2.0","id":…,"result":…}` or
  `{"jsonrpc":"2.0","id":…,"error":{"code":…,"data":"0x…"}}` (no message text; `data` only if hex);
  a batch returns an array in request order. A non-2xx answer or malformed body is status 2.
- **Method set `state-read` (exact):** `eth_chainId`, `eth_blockNumber`, `eth_getBlockByHash`,
  `eth_getBlockByNumber`, `eth_getBlockReceipts`, `eth_getTransactionByHash` (a result with a null
  `blockHash` — a mempool transaction — is returned as null), `eth_getTransactionReceipt`,
  `eth_getBalance`, `eth_getCode`, `eth_getStorageAt`, `eth_getTransactionCount`, `eth_getProof`,
  `eth_call`, `eth_createAccessList`, `eth_getLogs`. **`state-trace`** (Phase 2): adds
  `debug_traceCall`, `debug_traceTransaction`, `debug_traceBlockByHash` (the broker rewrites
  `TraceConfig` to `callTracer` or `prestateTracer`, a short `timeout`, `reexec` 0, no logger
  options — an unregistered tracer name is compiled as JavaScript) and `debug_executionWitness`.
  Nothing else, in any profile: no write, sign, admin, profiling, chain-control, mempool or test-node
  method. `debug_getRaw*` is excluded because it needs the whole `debug` namespace (`debug_setHead`,
  file-writing profilers); the builder RLP-encodes headers and receipts itself.
- **Caps (frozen for v1):** `eth_call` / `eth_createAccessList` always carry `gas = min(requested or
  30,000,000, 30,000,000)` and no state or block overrides; `eth_getLogs` uses a concrete range of at
  most 10,000 blocks (or the `blockHash` form), a non-empty address list of at most 8, a non-null
  `topic0`, at most 8 values per topic position; `eth_getProof` at most 256 storage keys; JSON depth
  at most 32.
- **Accounting:** builder-visible budgets count one unit per builder request (each batch element) and
  the bytes delivered. Retries and failover are charged only to operator and provider budgets in
  weighted cost units; exhausting an operator budget is status 2, so status 3 always means the job's
  own limits.
- **Retries:** transport errors and 429 → failover to another endpoint; lagging-node errors ("header
  not found", "missing trie node") → retry on another endpoint, at most two; execution errors (a
  reverted call) are answers. When every endpoint asked lacks the block or state, the fetch is status 2
  and final (*unanswerable*) only if two independent endpoints agreed or the block is beyond the
  pruning horizon; otherwise it is *source-lagging* (§9.2). An explicit block number above the head is
  refused (status 1) once two independent endpoints report heads below it; above one node's head only,
  it is status 2, source-lagging.
- **Keys:** key-bearing endpoints get no redirects, no Referer, no proxy; endpoints are logged by
  operator alias, errors with the URL stripped.

### 11.3 `blob/v1`

- **Config:** `abi.encode(uint64 maxBytes)`. **Request:** the 32-byte sha256 of the content.
- The operator configures mirrors as URL templates (`https://mirror.example/blobs/{sha256}`); the
  broker builds the URL from the id (builders never supply paths), spools the body to a quota'd file
  while hashing it, and returns bytes only after `sha256(body)` matches. **Response:** the raw bytes,
  at most `min(maxBytes, maxResponseBytes)`.

### 11.4 Broker robustness

The broker treats every builder as compromised:

- fixed-layout frames whose request bytes are capped at `max(maxRequestBytes, 64 KiB)` (plus the
  4-byte cap index); a larger header is rejected before allocating; partial frames time out;
- streaming parsers only; large bodies spooled to quota'd files and hashed incrementally;
- a global in-flight byte budget and a **reserved lane for held-lock work**, so no flood of witness
  jobs delays a lock this host holds;
- caches: RPC responses only for requests pinned to a block hash, keyed on the broker's canonical
  outgoing request, never errors, and every builder-visible budget charged as if each request missed
  (so cache state cannot be probed); type-tagged namespaces (ELFs, builder artifacts, witness blobs,
  RPC responses); non-public content keyed by trust domain; byte and entry caps with LRU on every
  cache;
- every log, verdict, TUI and `simulate` output passes through `redact_urls(sanitize_log(…))`.

The miner's connector, in turn, treats the broker as compromised: fixed-size strict frames, bounded
requests in flight, paced attempts (at most `64 + 16·t` connections in any `t` seconds, and each
endpoint's `max_concurrency`), and a cut-off on any protocol violation (§14.2).

## 12. Worked example: a builder that queries an RPC

The scenario: **the job submitter writes a program that contacts an RPC, runs arbitrary queries
against it, takes portions of the responses to serialize a complete witness, and returns it at the
end of its execution.**

### 12.1 The job

Statement: "at block `B` on Base, proxy `C`'s implementation is `I` (code hash `H`), and the `k`
slots its layout rule `R` names hold `V1..Vk`". `R` is one word: a rule id (byte 0) and a 248-bit
parameter `p`; rule 1 names slots `p … p+k−1`, rule 2 the `k` words of a `mapping(address ⇒ T)` at
slot `p` under key `I`. The requester knows `B` (from Base's finalized head), `C` and `R`. It:

- writes a **guest** that checks the header against `B`, reads the EIP-1967 implementation slot of `C`
  from proven storage to get `I`, proves `I`'s account to get `H`, derives the slot set from `R` and
  proven values, verifies every proof per §8.4, and commits `prefix ‖ header(schemeId = 1, B, C, R,
  k) ‖ outputs(I, H, k × (slot, value))`, where `I` is the low 20 bytes of the EIP-1967 slot (as the
  proxy reads it) and `H = EXTCODEHASH(I)`;
- writes a **builder** (type 1) that discovers the same things through the RPC to fetch the right
  proofs, and publishes it with `hemi-code` (§13);
- submits an exclusivity-window job (§5.6) with `inputData = WITNESS_JOB_TAG_V1 ‖
  abi.encode(WitnessJobV1{ builderType: 1, builderId: sha256(module), builderURIs:
  ["hemi-code://743111/0x…"], builderParams: abi.encode(uint64(8453), B, C, R, uint64(k)), sources:
  [{ class: keccak256("evm-rpc/v1"), config: abi.encode(8453, true, keccak256("state-read"), 300) }],
  limits: {...} })`, the journal-prefix marker, and a FIELDS binding pinning the whole 160-byte
  header (`journalFields = 0xffffffff ‖ 0x000000a0 ‖ 0…`, `expectedJournalHash = keccak256(header)`);
- keeps `k` small enough for the fulfil to stay under the DA cap (about 20 slot/value pairs at the
  default 2,048-byte cap), or commits a digest of the values instead.

The reference: `reference/proxy-slots` (statement, guest) and `sdk/examples/proxy-slots` (builder).

### 12.2 The builder

```rust
// Witness builder (wasm32, executed by the miner before any lock, never proven).
#[no_mangle]
pub extern "C" fn run() -> i32 {
    let ctx = BuilderContextV1::read();
    let (_chain, st) = Statement::from_builder_params(&ctx.builder_params)?;
    let at = json!({"blockHash": st.block_hash});
    let rpc = |method: &str, params: Value| fetch_json(0, method, params);   // untrusted, parsed here
    // 1. The header for B, RLP-encoded by the builder (the guest checks keccak(header) == B).
    let header = rlp_header(&rpc("eth_getBlockByHash", json!([st.block_hash, false]))?);
    // 2. Adaptive: the implementation slot, then the implementation's layout.
    let imp = rpc("eth_getStorageAt", json!([st.proxy, EIP1967_IMPL_SLOT, at]))?;
    let slots = st.rule.slots(low20(imp), st.k); // the guest's own code
    // 3. Proofs for everything the guest will use.
    let p_proxy = rpc("eth_getProof", json!([st.proxy, [EIP1967_IMPL_SLOT].concat(&slots), at]))?;
    let p_impl = rpc("eth_getProof", json!([address_of(&imp), [], at]))?;
    // 4. Serialize exactly what the guest consumes.
    witness_write(&scheme1::Witness {
        header_words: st.header_words(), headers: [header], accounts: [p_proxy, p_impl], ..
    }.encode()); // after running the guest's statement over it
    0
}
```

### 12.3 Why arbitrary queries are safe

- **Soundness.** A lying or stale RPC, or a buggy builder, yields a witness the guest rejects or a
  header that differs from the binding: no lock. The guest re-derives the implementation and the slot
  set, so a wrong `eth_getStorageAt` answer cannot redirect the question (§8.2).
- **Adaptivity.** Queries may depend on earlier responses to any depth; each costs budget.
- **Nondeterminism.** Different nodes, a reorg between runs: `W` may differ between runs and miners;
  each miner proves the `W` it persisted.
- **Exfiltration.** The builder holds no secret, and **anything it receives can be published** by the
  requester (the guest can copy `W` into free journal bytes): hence re-serialized responses, no error
  text, no job identity in the context, and dedicated node listeners.
- **Abuse of providers.** Frozen caps, weighted budgets, global rate caps, and separation from the
  miner's chain RPC (§11).
- **Flaky RPC.** A transient failure is retried within bounds (§16); at worst a missed job.

### 12.4 Variants

- **Event proofs** (`sc.event`): `eth_getLogs` to find a log, `eth_getBlockReceipts` for the
  receipts-trie proof; the guest applies §8.4's receipt duties and pins or re-derives *which* log.
- **View calls** (`sc.call`): `eth_createAccessList` to discover the state a call reads,
  `eth_getProof` for each account and slot; the guest runs the call with §8.4's call context and
  completeness rules.
- **Whole blocks** (Phase 2, `state-trace`): `debug_executionWitness` or a prestate trace plus the
  block and its parent header.
- **Several chains:** one capability per chain, each sub-witness anchored per §8.5.

## 13. Storing artifacts on Hemi (`hemi-code`)

A requester can store its builder on the HemiProve chain itself, as contract code. It is then
available for as long as a working Hemi RPC is — the dependency every miner already has to see the
job — with no requester server to keep up while the job stays Open.

### 13.1 Why contract code

Calldata and event logs are cheaper but live in the chain's *history* (old blocks, log indexes,
providers' `eth_getLogs` range limits). Contract code is *state*: every full node, archive or not,
serves it at the latest block with `eth_getCode` (snap sync downloads all bytecode; history expiry
removes only bodies, receipts and logs). Hemi enforces EIP-6780 (the deploy runbook lists it, with
EIP-7702, among the chain confirmations to record on 743111 and 43111), so a contract self-destructs
only in its creating transaction. Under EIP-7702 a delegated account's code reads as a 23-byte
designator `0xef0100 ‖ address` that its key can re-point; code beginning with `0x00` has no
reachable instruction and cannot be delegated, so **a `0x00`-prefixed read is permanent** — and the
prefix check on the manifest and on every chunk is what makes that true.

### 13.2 Format

- **Chunks:** at most 24,575 bytes, deployed as a data contract whose runtime code is `0x00 ‖ chunk`
  (a no-op if called; within EIP-170's 24,576; avoids EIP-3541's `0xEF` rejection). Any deployment
  method works; the miner only reads code.
- **Artifact manifest:** one more data contract whose runtime code is exactly `77 + 20n` bytes:
  `0x00 ‖ ARTIFACT_MANIFEST_TAG_V1 (32 B) ‖ length (uint64) ‖ sha256 (32 B) ‖ n (uint32) ‖ n
  addresses (20 B each)`, integers big-endian, `ARTIFACT_MANIFEST_TAG_V1 =
  keccak256("hemiprove.artifact-manifest.v1")`. Chunks concatenate in order; the addresses are
  distinct and none is the manifest's own; at most 1,224 chunks (30,079,800 bytes).
- **Locator:** exactly `hemi-code://` ‖ chainId ‖ `/0x` ‖ 40 characters from `[0-9a-f]`, chainId the
  canonical decimal of a uint64 (no leading zero). Byte-exact matching; any other spelling (case, an
  EIP-55 checksum, a trailing `/`, query, fragment, userinfo, port, percent-escape) is malformed and
  ignored. At most 75 bytes. The chain id must be the HemiProve chain the job is on.
- **Identity:** the manifest's `sha256` is the sha256 of the assembled bytes. Types 1 and 3:
  `builderId` must equal it. Type 2: the image id computed from the bytes inside the sandbox must
  equal `builderId`. Anyone may publish a copy; a wrong manifest can only fail verification.

### 13.3 Where reads go

- To an operator-configured **artifact endpoint** (`[artifacts] rpc_url`), under the separation rule
  of §11.1 (never the chain-RPC provider account or key, never the same provider from the same egress
  IP, never the same node process): a flood of artifact reads must not delay claims, fulfils or
  receipt polls for a held lock. It is the operator's own node, or a provider that does not carry the
  miner's chain traffic.
- zkminer checks its `eth_chainId` at startup, paces it with its own limiter (`[artifacts]
  max_requests_per_sec`), and serves held-lock reads first. With no artifact endpoint configured,
  `hemi-code` entries are ignored (logged once).
- The reader runs in the broker, under the broker's uid; the endpoint is admitted by role in the
  broker's network floor (§14.2). It must be globally routable outside dev mode (§14).
- Whoever operates the endpoint sees which host read which manifest, and a requester can make a
  manifest unique per job cheaply (a small manifest over shared chunks, ~0.25M gas). That is why it
  must not be requester-operated.

### 13.4 Miner fetch

Every read of one attempt uses one block, **fixed by hash** (`eth_getCode(addr, {"blockHash": H})`), so
a reorg during the attempt cannot mix two forks. The attempt reads at the **safe head** first: publishers
submit a job only once every deploying transaction is at or below safe (§13.5), so an honest artifact
exists there, and any failure found there is final. Only when the manifest is empty at safe does the
attempt re-read at the head (also pinned by hash); a success there is served (correctness rests on
`sha256`), and a failure there is per job and recorded as pending with its block number and hash. A
later fetch promotes a pending failure to a remembered one once the safe head has passed that block
and the block at that number still has the recorded hash, and drops it if the hash differs.

1. Parse the locator; ignore it if malformed or for another chain. At most one `hemi-code` locator per
   job is read past step 2.
2. Read the manifest with `eth_getCode`, the response capped at 24,576 code bytes while it is read.
   Check, in order, in 64-bit arithmetic: code length ≥ 77; the `0x00` prefix; the tag; read `n`;
   `1 ≤ n ≤ 1,224`; code length exactly `77 + 20n`; `length ≥ 1`; `⌈length / 24,575⌉ ≤ n ≤ length`;
   `length` ≤ `[artifacts] max_builder_bytes`; for types 1 and 3, `sha256 == builderId`; the addresses
   distinct and none the manifest's own. No chunk is read until all pass.
3. **Charge before reading:** `length` bytes and `n` chunk reads (`n + 1` with the manifest) are added
   to the job's simulation cost and admission (§17) is re-run; probation callers are clamped unless
   the artifact is cached.
4. Read the chunks in JSON-RPC batches of at most 256, each response capped at 24,576 code bytes: the
   `0x00` prefix and a body of 1–24,575 bytes; abort as soon as the running total exceeds `length`;
   at the end require the total to equal `length`.
5. The broker computes `sha256` over the assembled bytes itself, requires it to equal the manifest's,
   and inserts the artifact into the cache under `(type, builderId)`; nothing a builder process
   reports is ever a cache key.

**Failures** (the artifact rows of §16):

- Malformed locator, or another chain: ignored.
- **Empty manifest** (unpublished, reorged away, wrong address): transient; retried at most three times
  per job with backoff, then permanent for the job.
- **Present but invalid** (structural failure, an empty or invalid chunk, bytes that do not hash to its
  own `sha256`): permanently bad, remembered by manifest address across jobs and callers — **only when
  read at a block at or below the safe head** (at the head, a reorg could replace the code at that
  address, so the verdict is per job and pending until promoted as above).
- **Valid but for another artifact** (`sha256 ≠ builderId`): bad for that `(manifest, builderId)` pair,
  so a decoy job naming someone else's good manifest cannot make it fail for others; remembered under
  the same safe-head rule.
- **Endpoint errors, timeouts, rate limits, pruned state:** operator-side, retried at a new fixed
  block, never counted against the caller (except a caller's own exhaustion of its artifact share).
- A reorg can make an artifact unavailable (for good, if the publishing transactions are never
  re-included), never wrong.

**Fetch order** for any builder: local cache → operator mirror → `hemi-code` → (Phase 2) requester
URLs through the artifact egress (§14.3).

### 13.5 Publishing

`zkminer artifact publish <file> --kind builder|elf --rpc-url <url> --chain-id <id>` (or the same in the
requester SDK). The pacing and key rules below are **MUSTs of the published format** for every
publisher, because Hemi's guardian pauses the HemiProve router for everyone once the unposted DA
backlog reaches about 2.75 MB, whatever its source, and above 3.2 MB the sequencer filters large
transactions.

- **Input check:** `--kind` must match the file before anything is sent: a builder parses as a WASM
  module; an ELF is a risc0 `R0BF` program binary whose user and kernel ELFs are RV32 and load, or a
  bare RV32 ELF. Publication is permanent.
- **Key:** an encrypted keystore with a password from a TTY or fd, or an external signer; an
  environment variable only with in-place scrubbing and `PR_SET_DUMPABLE(0)`. Never the miner's
  `[wallet]`, never `ZKMINER_PRIVATE_KEY`, never argv. It refuses the configured prover address (read
  from a non-secret config field) and any address staked as a prover or registered as one's operator
  (checked on-chain), and any key with pending transactions it did not send. Under the DA throttle a
  stuck chunk also blocks every later nonce of its sender, so a chunk signed by a prover key would
  stall that prover's fulfils. zkminer's publisher implements the encrypted keystore (Web3 Secret
  Storage), its password from `/dev/tty` with echo off or `--password-fd` (3 or above). It takes no
  key from the environment and has no external signer yet. *Staked* means `getProverStake(key)` has
  a non-zero `totalStaked`, `lockedCollateral` or `unstakeAmount`. *Operator* means an
  `OperatorAuthorized` whose `operatorAuthorizations(prover, key)` has a non-zero bitmap and
  `authorizationNonce == proverAuthNonce(prover)`; a frozen operator still counts. *Pending* means
  `eth_getTransactionCount(key, pending) ≠ latest` before the first send, and a pending nonce above
  the publisher's own next nonce before each later send. `--password-fd N` is taken at the start of
  the process, before anything else opens a descriptor: N ≥ 3, open, readable, a pipe or regular
  file, never a terminal or socket. The keystore's parameters are checked before any work (version
  3, aes-128-ctr, 16-byte IV, 32-byte ciphertext and MAC, dklen 32–64, scrypt within 512 MiB and
  2^24 blocks, PBKDF2-HMAC-SHA256 at most 10^7 rounds). The password, derived key and key are zeroed
  after use, and the process leaves no core dump.
- **RPC:** `--rpc-url` (or `--rpc-url-file`, or `ZKMINER_PUBLISH_RPC_URL`, since argv is visible to
  every local user and the URL may carry a key) is required, and must be `https://` outside
  developer mode; it refuses `chain.rpc_url` while a miner instance lock is held, and uses its own
  limiter. **The publisher trusts this RPC** for the pacing readings and the key checks.
  `--verify-rpc-url` names a second provider: each deployment must show there in the same block with
  the same code before the next chunk is signed (or the run stops after 10 minutes), and the
  read-back is repeated there. It works standalone, without a zkminer configuration. Every request
  goes through the network guard (the URL checked, each address vetted and pinned, no proxy, no
  redirect followed). A node on loopback or the LAN is reachable only with `[dev] private_network`
  for that very chain (`[dev] chain_id` = `[chain] chain_id` = `--chain-id`). "A miner instance lock
  is held" means another process holds the `flock` on `~/.zkminer/miner.lock`.
- **Cost preview** before sending: L2 gas at the chosen tip, the L1 data fee from `GasPriceOracle`, and
  the balance the pool requires for an in-flight chunk (gas limit × max fee, plus its L1 fee).
- **Pacing:** one chunk transaction in flight, at most one per block; send only while the DA backlog
  (measured as the contracts' `check-l2-lag.sh` measures it: the sum of `l1GasUsed / 16` over user
  transactions in (safe head, head]) plus its own unmined estimates is **under 250 KB** (a tenth of
  the backlog page level), the safe-head lag is at most 300 s, the router is not paused, and the head
  is at most 60 s old. That is about twenty minutes per MiB; publishing is not time-critical. The
  backlog is read as the miner reads it: the per-block count over (safe, head], at most 150 blocks,
  else unknown, which means wait. On a local test network, `[dev] da_backlog_bytes` stands in for
  it. "At most one per block" means a send only on a head later than the previous send's. Sends are
  also at least one block time apart by the local clock, whatever the RPC reports: 12 s on Hemi;
  elsewhere measured over the last 64 blocks, at least 1 s outside developer mode. `--block-time-ms`
  sets it, never below that minimum outside developer mode. `[dev] da_backlog_bytes` applies only on
  a chain without a deployment, or on 743111 when the RPC is a loopback address (a local fork).
- **Chunk size and fees:** each chunk is sized so `GasPriceOracle.getL1GasUsed(unsignedTx) / 16` of
  the exact transaction is at most 19,500, below the first throttled level's 20,000 cap: a chunk
  starts at 23,000 bytes (which estimates at about 19,900 when incompressible, Appendix B) and
  shrinks in proportion until the oracle's estimate fits, about 22,500 bytes of incompressible code. Both fee fields are explicit; the tip is the measured
  inclusion floor (about 10 wei on 43111; measured from recent blocks on each chain). A chunk unmined
  while the backlog is under the threshold and the lag is low has a tip below the floor: bump it at
  the same nonce. Only a backlog above the throttle threshold means waiting; chunks are never
  reshaped to squeeze through a throttle, and any replacement reuses the stuck nonce. Chunks are
  sized against a transaction whose nonce, gas and fee fields are at their longest RLP: 23,000 bytes
  first, shrunk in proportion while the oracle's estimate is above 19,500. A chain without the
  oracle uses the RPC-free upper bound. The tip is the lowest effective tip of user transactions in
  the last 20 blocks (else `eth_maxPriorityFeePerGas`), with `maxFee = 2 × baseFee + tip`. A chunk
  unmined for 3 blocks while the gate is open is replaced at its nonce with both fields raised by at
  least an eighth. The tip never goes past 64 times the floor (and at least 1 gwei); at that cap the
  publisher only waits. A plan of more chunks than a miner's per-job artifact budget admits is
  refused: miners count chunk reads from 16,384-byte chunks, `⌈max_builder_bytes / 16,384⌉ + 1` (257
  for 4 MiB), and a manifest over it is `NotAdmitted`, deferred for ever. At most 16 replacements
  per nonce, the max fee never above 8× the starting base fee plus the tip cap (above that the
  publisher waits). A refused replacement leaves the pooled fees as they were.
- **Deploy and verify:** chunks first, the manifest last; addresses from receipts, never precomputed;
  every receipt's status checked (an out-of-gas creation spends the nonce and leaves the address
  empty: redeploy at a new nonce); with a CREATE2 factory, identical code already present is success.
  Wait until every deploying transaction's block is at or below the `safe` head with its hash
  unchanged, then run the miner's own fetch (§13.4) on the locator, and only then print the locator,
  `sha256`, `length`, `n`, the addresses and the total cost — plus the `builderId` for a builder, or
  for an ELF the `addStorageURI` arguments (§13.6). Warn when `length` exceeds the published default
  `max_builder_bytes`, and for `--kind elf`, that Phase-1 miners ignore `hemi-code` ELF entries.
  Submit the job only after this. The gas limit is `eth_estimateGas` + 10% + 10,000. A failed
  creation is redeployed at the next nonce with at least twice the gas, at most 3 times. zkminer
  deploys with plain CREATE. A deployment whose block was reorged is followed through its receipt;
  if it is gone, the run fails and prints nothing. The miner's fetch is §13.4's read at the safe
  head, pinned by hash, with the broker reader's own check functions (`parse_manifest`,
  `chunk_body`, `Assembler`), run inside the publisher (the broker needs the miner's sandbox and the
  operator's endpoint). The assembled bytes must equal the file. For an ELF it prints
  `addStorageURI(<programId>, 3, locator, keccak256(elf))`. With `--progress FILE` every mined
  deployment is recorded. A later run of the same artifact to the same chain reuses recorded chunks
  from the start, while their receipt and code at that block match, plus the manifest when every
  chunk was reused, and sends only the rest. Without it, a re-run sends every chunk again.

The full cost arithmetic is in Appendix B: about 231M gas per MiB; at a tip near the inclusion floor
the L1 data fee dominates — about 0.0009 ETH per MiB at a 0.062 gwei L1 base fee, about 0.4 ETH at
30 gwei; negligible on the testnet.

### 13.6 Guest ELFs (Phase 2)

ELFs can use `hemi-code` once the ELF fetch runs behind the broker (§14.8), with the same endpoint and
rules:

- the program's registrant (or its family admin while that admin co-controls the program) calls
  `addStorageURI(programId, 3 /* Custom */, "hemi-code://…", keccak256(elf) or 0)`, or lists the entry
  in `registerProgram`'s `initialURIs`; the URI is 1–512 bytes; a program holds at most 8 URIs; none
  can be added to a Revoked program; the call emits `StorageURIAdded`; registration is first-come, so
  a squatted `programId` cannot be given one;
- zkminer treats only Custom entries as `hemi-code` (today it skips Custom entries and refuses
  non-http(s) URIs of the HTTP type) and tries them before the program's other URIs;
- the manifest's sha256 only checks integrity; identity is unchanged (the risc0 image id, the registry
  `elfHash` for SP1, any non-zero `contentHash` — all keccak256 of the ELF);
- at most one `hemi-code` URI per program is read past its manifest; verdicts are cached by manifest
  address; size is charged before chunk reads; a `hemi-code` ELF cap applies (one manifest holds at
  most 30,079,800 bytes, far below zkminer's 248 MiB ELF cap); the pre-claim ELF fetch budget (90 s
  today) must allow `n + 1` reads.

These rules matter more for ELFs than for builders: every job, inline ones included, fetches its
guest ELF, and anyone can register a program with up to eight URIs.

### 13.7 Concerns

- **Permanent and public:** nothing published can be deleted; never publish anything secret.
- **DA load:** unpaced publishing pauses the router for everyone; the protocol cannot enforce pacing
  on a third-party publisher (§7.3 documents the rule; the runbook notes the signature).
- **State growth** on Hemi, paid for in gas by the publisher.
- **Scope:** this makes the builder's bytes as available as Hemi; the builder's data sources are
  still off-chain.

## 14. Egress security

Any job that makes the miner fetch something is an SSRF surface: a malicious job wants the connection
aimed at internal resources (cloud metadata, admin panels, databases, the LAN, the miner's own
services). **One hardened path:** every fetch for builders and artifacts goes through the broker; a
second, un-hardened path is how guards get bypassed.

**The rule: a miner never reaches a non-public destination on a job's behalf.** Every connection that
job content can cause — ELF downloads from ProgramRegistry URIs, builder fetches, `hemi-code` reads,
mirrors — goes only to globally routable addresses outside the host's own addresses (public NAT
addresses included), its connected prefixes, its sites (the /32 around its global IPv6 addresses by
default, the /16 around its global IPv4 interface addresses) and the operator's `[egress]
internal_ranges`, that do not answer a hop-limited probe sent right before the connection
(`near_hop_limit`, default 2: the host's router and anything it hairpins to; when the probe gets no
answer, a check connection whose FIN, limited to the same hop count, must go unanswered). Names pass host-name hygiene and are resolved
over DNS-over-HTTPS at fixed public resolvers, never the host's resolver (§14.7), and the vetted
address is pinned for the connection. It fails closed: while the host's public address on a routed
family is unknown (neither confirmed by the reflectors nor stated in `[egress] public_addresses`),
nothing goes out over that family. A public address is confirmed by the HTTPS reflector, or by both
DNS reflectors alike unless the HTTPS reflector's connection was answered by an impostor; a
confirmation lasts 10 minutes and belongs to the uplink it was made on. Where the host's own
numbering cannot tell internal from public space — a global IPv4 address on an interface, or an
uplink that is not plainly physical (any interface kind other than a NIC, bridge, bond, team, VLAN,
macvlan, ipvlan, veth or VRF; ppp that is not PPPoE; a default route in an ordinary table other than
main or default; a nexthop object it cannot resolve) — the miner refuses to start in public mode
until the operator states `[egress] internal_ranges` (an empty list says there are none), and if
that arises later (a VPN that comes up after start), makes no such connection until the ranges are
stated or the condition clears. This holds
for operator-configured endpoints too: a builder can ask an operator's node anything its method set
allows, so a node on loopback or the LAN would expose whatever that node can reach. The **only**
exception is the default-off developer setting `[dev] private_network = true` together with
`[dev] chain_id` naming the chain it is meant for (equal to the RPC-confirmed chain id; shared by the
miner and the broker it launches; refused on Hemi mainnet; announced by a warning at every start), which
local test networks and test scripts use. There is no environment-variable or command-line bypass.
A malicious guest and builder could otherwise read an internal service and commit what it returned
to a public journal. A compromise of the broker does not widen this: the broker cannot make a
connection, and the connector, in the miner, makes only connections to the operator's configured
endpoints at addresses the floor admits. Nor does a compromise of a worker that runs a requester's
guest: it can make or reach no socket, Unix ones included (§10.3).

### 14.1 Current state and gaps

zkminer's ELF fetch (`crates/zkminer-chain/src/programs.rs`) already rejects, in `ip_is_blocked`,
ULA (covering `fd00:ec2::254`), every embedded-IPv4 form (mapped, compatible, SIIT, NAT64, 6to4,
Teredo), CGNAT, `0/8`, `198.18/15`, documentation ranges, multicast, `240/4`, `192.0.0/24`,
`192.88.99/24`, `fec0::/10` and Azure's `168.63.129.16`; resolves once and pins the address; ignores
proxies; and follows redirects by hand, re-checking each hop. Gaps:

- **Allow-only-globally-routable** instead of a blocklist (`is_global` semantics; the blocklist
  misses, for example, `100::/64`, `2001:2::/48`, `3fff::/20`, `5f00::/16`).
- **`ZKMINER_ELF_ALLOW_PRIVATE_URLS`** disables checks and pinning on every hop. *(Removed: replaced by
  `[dev] private_network`; see the rule above.)*
- **Schemes and ports:** http and any port are allowed; redirects up to 5 hops, each accepting http.
- **Hairpin and on-link:** a global check passes the host's own public or NAT address and on-link
  global neighbours (a NAS or BMC with a global IPv6 address in the miner's /64).

### 14.2 The connector: the broker's network floor

The broker has no network of its own (§10.2). When it needs a connection it sends the miner's
**connector** a fixed-size, versioned request naming an operator endpoint **by index** (role, index,
the port it expects, a request id) over a dedicated socket; it never supplies a host, address or name.
The connector, in the miner, checks the index, role and port against its **own** copy of the broker
file (loaded by the miner in its network mode, never read back from the broker), resolves the host
name itself (§14.7), admits each address — it must lie in the endpoint's role entry and, in public
mode or for any DNS answer, pass netguard's floor over the miner's host facts: globally routable,
outside the host's own and public (NAT) addresses, connected prefixes and on-link routes, the IPv6
and IPv4 sites, the internal ranges, routes off the default path, local routes, destination policy
rules, NAT64 prefixes, the DNS servers and the deny CIDRs, on a family whose public address is
known, confirmed by a per-destination kernel route query (with the destination port and, for IPv4,
the source the kernel picks) — then, right before connecting, refuses an address that answers the
near-hop probe (with its check connection when the probe gets no answer), connects, and returns the connected socket (`SCM_RIGHTS`). A malformed frame, a
descriptor sent to the connector, more than 64 requests in flight (a request is in flight until its
answer is handed to the socket, so unread answers count), a reused request id, more than 8 requests
for missing endpoints within a minute (counted before the refusal is answered), an answer left
unread for longer than a request's budget, or a failed answer write while the broker keeps sending
(it shut its reading side) **cut the broker off**: its socket is shut first (so nothing more reaches
it), the answer writer and the requests still being served are aborted, its cgroup killed, witness serving stopped (`PAGE: WITNESS-BROKER-CUT-OFF`). So
is a broker that closes its connector socket and is still running 5 s later. However the session
ends, every builder runner registered with the broker is killed with it, and one registered later
at once: the broker can pass a runner any descriptor over its job socket, and such a socket must not
outlive it. The connector's socket has the kernel's minimum send buffer, so a broker that stops
reading leaves at most 64 sockets with the miner and about six in its own receive queue before it is
cut off. The broker cannot point a handed socket anywhere else (§10.2).

Role entries are held to the same rule: outside dev mode a role entry whose address or CIDR is not
global, or overlaps the host's own addresses or connected prefixes, is refused when the configuration
loads — by the miner, before it starts the broker, and by the broker. The broker checks every socket
it is handed against its own copy of the floor as a second layer (by flattened prefixes: its sandbox
denies netlink). Where the operator has root, an nftables floor around the miner's connections is a
further layer.

In cloud deployments, block the metadata service inside the instance with nftables as well, and set
metadata options (IMDSv2 required, hop limit 1, or the endpoint disabled): security groups and NACLs
do not filter link-local traffic.

### 14.3 Requester-chosen URLs (Phase 2)

`https`/`ipfs` `builderURIs` (and, later, Tier-2 content) go through the **artifact egress**, so a
requester serving a unique URL per job cannot map simulating hosts to the staked prover that later
locks and target it:

- the broker resolves and vets the name, then asks the proxy to `CONNECT <vetted-ip>:443` — never a
  hostname, which the proxy would re-resolve (DNS that answers by resolver source would otherwise
  reach the proxy's network) — keeping TLS end to end with SNI and certificate checks on the original
  name; alternatively the proxy enforces allow-only-global itself and is documented as the boundary;
  without `[artifacts] egress_proxy`, requester URLs are skipped;
- HTTP/1.1 only, `Accept-Encoding: identity`; every hop https, port 443, no userinfo, at most 3 hops;
  `builderURIs` tried on a fixed schedule, at most one per attempt;
- names resolve through the egress (DoH) at a resolver that does not send EDNS Client Subnet; no TLS
  resumption or connection reuse across jobs for requester hosts; a constant User-Agent without a
  version; all address families through the egress;
- IPFS through operator-configured gateways via the egress, CIDv1 base32 syntax-checked, the URL built
  by the broker.

### 14.4 Parser-level hygiene

Reject `file:`, `gopher:`, `dict:`, `ftp:`, `redis:`, `ldap:`; reject `userinfo`, integer/octal/hex
hosts, single-label names and internal suffixes (`.local`, `.internal`, `.cluster.local`,
`metadata.google.internal`); full TLS certificate validation against the original hostname, always;
decompression caps on decompressed bytes; content ids syntax-checked and every URL built by the
broker; the broker never parses attacker-supplied programs or DAGs (it hashes raw bytes; decoding
happens in the sandbox).

### 14.5 Content gate ≠ SSRF defense

The content-hash gate stops a malicious URL from injecting data, not from probing (response timing
and connect success make the miner a port-existence oracle; DNS lookups exfiltrate). It sits on top
of the network floor, never instead of it.

### 14.6 Abuse limiting and observability

Per-job and per-source byte, request, cost and wall-time quotas; connection concurrency and
connect-rate limits; a per-endpoint concurrency cap. A scan signature (many distinct host:port
connects, a burst of connect-refused) aborts the simulation, skips the job and lowers the caller's
credit (§17.4). Every egress is logged with the job id and the endpoint alias; spikes of
policy-denied connects alert. The host's sensitive endpoints (a local chain node, the sp1-gpu-server
IPC, local artifact and mirror nodes) are reachable from the broker only through their role entries.

### 14.7 DNS

A dedicated resolver for broker endpoints (no `/etc/hosts`, no mDNS, no split-horizon zones): the
connector, in the miner, carries the stub resolver (DNS over TCP, a fresh connection per query,
random ids, strict answer checks, fuzzed) aimed at `[dns] servers` (default: the nameservers in
`/etc/resolv.conf`) and asked only operator endpoint names; the broker resolves nothing. Validate every returned record
(owned by the queried name or a name at most 8 `CNAME` records from it, in any order) and cap
query volume. **A name only ever resolves to a global address:** an endpoint configured by host name
without explicit `cidrs` admits only answers that are global and outside the deny CIDRs, the
connected prefixes and the host's own addresses (at startup and on every re-resolution, every
`reresolve_secs`); a local or LAN node must be configured by IP literal or explicit `cidrs`, which
then form its role entry. A stub at `127.0.0.53` still applies systemd-resolved's own `/etc/hosts`,
LLMNR and mDNS handling; the global-only filter is what makes that harmless.

Requester names — ProgramRegistry storage URIs, their redirects, and the fixed IPFS and Arweave
gateway names — never reach the host's resolver, `/etc/hosts` or NSS: in public mode netguard
resolves them over DNS-over-HTTPS at Cloudflare, Google and Quad9 addressed by IP literal (or
`[egress] doh_resolvers`), with EDNS Client Subnet source prefix 0, reading only the name's CNAME
chain, and on IPv6-only hosts synthesizes AAAA from A under the NAT64 prefix. Developer mode uses the
system resolver.

### 14.8 Phasing of the egress work

| Step | Phase | Applies to inline jobs? |
|---|---|---|
| Broker, network floor, operator-endpoint roles; builder fetches and `hemi-code` reads through it | 1 | no |
| Allow-only-global predicate, host-name hygiene, own-address and connected-prefix denial and address pinning in today's ELF fetch (public URLs unaffected); `ZKMINER_ELF_ALLOW_PRIVATE_URLS` removed in favour of `[dev] private_network` | 1 | yes, compatible |
| ELF fetch behind the broker, with a migration: an operator ELF mirror keyed by image id / `elfHash`; an http-deprecation release that warns before it refuses | 2 | yes |
| Artifact egress for requester `https`/`ipfs` URLs (§14.3) | 2 | no |
| Tier-2 requester content | 3 | no |

Witness serving stays disabled in code until the steps of its phase are in place and the self-test
(§10.3) passes on that host.

## 15. Retention and the prove path

### 15.1 The store and the bundle

- **The store:** `[retention] dir`, on its own filesystem with a quota (recommended); otherwise zkminer
  enforces its own quota and a free-space floor on the shared filesystem and refuses new bundles below
  it. Never tmpfs, `/dev/shm` or an overlay. The root carries an identity record (store UUID, chain
  id, router, prover), and the miner holds an exclusive lock on it for its whole life. Quotas cover
  bytes and inodes.
- **A bundle** is a directory `<jobId>/<descriptorHash>/<prover>/v<n>/` holding `w.bin` and a
  versioned `bundle.json`: the full descriptor (verified against `descriptorHash`) and the submit
  transaction hash; the prefix flag; the image id; per po2 the journal (≤ 32 KiB), `sha256(J)`, cycles,
  exit code and serialized segment bytes; `sha256(prefix ‖ W)` and `|W|`; the `sys_rand` rule
  (`sys_rand_rule`: the SHA-256 of the rule's domain); the keccak po2; the build of every prove
  worker that may prove it and of the execute
  worker that produced its journals (the prove workers as each names itself; the execute worker as
  its handshake names it before any guest ran in it; never a placeholder); the measured execute
  time per po2; the sha256 of the retained ELF (a read through the bundle checks it, so proving a held
  lock derives no image id); the prover; the block at which it was created.
- ELFs (and, later, placed content) are content-addressed in a shared, refcounted area — never copied
  per bundle.
- Writes go to a temporary directory, files fsynced, renamed into place, the parent fsynced. **A
  published bundle is immutable**; a new execution result is a new version. Every read verifies
  `sha256(W)` and the ELF's image id.
- The bundle makes recovery independent of chain history: the descriptor is retained, so a lock taken
  long after submission can be re-driven after a restart even where nodes have pruned old blocks.

### 15.2 Availability, pins, revalidation, deletion

- **Store states.** *Unavailable* (root absent, wrong mount or identity, any read error such as EIO,
  EROFS or ENOENT): keep every lock, `PAGE: RETENTION-UNAVAILABLE`; the recovery room rule releases a
  lock only as its window closes. *Missing* (an available store with no complete entry) or *corrupt*
  (a re-read still fails verification): `PAGE: BUNDLE-MISSING` naming the lock, `D + G` and the path;
  wait until `D + G` minus the release margin; then, if every declared capability is Tier 1 and the
  builder is cached or mirrored, optionally **salvage** (rebuild `W`, execute, check the binding, and
  prove only if it holds — the one exception to invariant 2, allowed because the loss is the miner's
  own); otherwise release. An *adopted* lock (found on chain, with no journal entry and no bundle) is
  released at once only if the prover key has no pending transactions this process did not send;
  otherwise it is kept until the room rule decides. A *poisoned* store (a failed fsync) refuses every
  write but serves the version a readable pin names, or the last durable pin of a key whose re-pin
  failed, every byte re-verified; nothing is pinned,
  unpinned, deleted or evicted until a restart reopens it.
- **Pins.** A pin is a record in the store, fsynced before the claim intent is journaled and before the
  lock transaction is signed. A pin records the job's reopen count, the chain time it was taken and,
  once confirmed, the lock block. It is removed only on a terminal read; a read showing a higher
  reopen count; a read at or after the lock block showing another prover or none; or, for a claim
  never confirmed, a read from a block mined at least the claim-intent age after the pin (by that
  block header's timestamp). A read showing the job locked by us is never such evidence, and an abandoned claim
  attempt keeps its pin while an earlier claim of ours is unresolved. A held lock with no readable
  pin is proven from the store's latest complete version for (job, descriptor, prover), which
  recovery then pins. The store, not the lock journal (which is not fsynced and can be lost), is the authoritative index
  recovery uses.
- **Single flight.** One simulation per jobId (the in-flight map is keyed by jobId); a pinned job is
  never re-simulated; a re-lock of the same job reuses its pinned bundle after revalidation.
- **Revalidation** before a lock on a retained bundle, against the host as it is now: the enabled
  cards' po2 set, the `sys_rand` rule, the keccak po2, the build of every worker binary that may prove
  it. A missing po2 is executed from the retained `W` (never by rebuilding). A held witness lock waits,
  within its budget, for a card at an executed po2 rather than proving at an unexecuted one; Settings
  warn before changing a card such a lock depends on.
- **Eviction.** Nothing is evicted until this process has completed one full store scan and one
  chain recovery pass whose chain scan was complete, and has pinned the bundle of every witness lock
  that pass found; the bundles of jobs that pass left undecided are spared until a later pass
  decides them. Pinned
  bundles are never evicted. Every other bundle is a cache: evicted lowest-value-first under pressure,
  never counted against admitting new jobs. The per-caller byte cap applies only to bundles of Open
  jobs this host may lock. Content is stored once per trust domain and refcounted.
- **Deletion** only when an authoritative read shows the job terminal (Fulfilled, Cancelled, or Open
  with `reopenCount ≥ MAX_REOPEN_COUNT`) and no pin exists, re-checked under the store lock. A risen
  reopen count only unpins. Lifetimes tied to another prover's lock use its pause-credited deadline
  read from chain (plus up to 24 h of `extendLocksForDowntime`). A binding bid's bundle lives as long
  as the bid binds (`maxBiddingDuration` plus pause credit plus up to 7 days of pause; the whole pause
  for a won round left unsettled), and the miner settles its own winning round at once.
- **Verdicts** persist across restarts, are fixed-size with no attacker strings, and are dropped when
  the job is terminal or after a TTL. A post-lock verdict lasts until its job is terminal (never by
  TTL); post-lock verdicts and tallies are never refused for the quota (only a full filesystem
  refuses them).

### 15.3 The prove path: execute, compare, prove

- The prove env is built exactly as today (input, derived seed, `segment_limit_po2`) with **no
  coprocessor callback**: the measure path's keccak-audit callback empties `pending_keccaks`, which
  would make the session unprovable.
- The worker runs `ExecutorImpl::from_elf(env, elf)?.run()` with `segment_path` set to
  `<segment_root>/<slot>` (an operator-configured, non-tmpfs filesystem distinct from retention and
  the journal, wiped when a worker spawns), applies the measure checks to that session (Halted(0), a
  non-zero output digest, assumptions limited to the keccak root, keccak claim digests recomputed from
  `pending_keccaks`), checks `sha256` of the input it received against the bundle, compares
  `sha256(journal)` with the expected hash, and only then calls `prove_session` on that same session,
  reusing it across the invalid-proof retries. risc0 already executes fully before proving, so the
  comparison costs no extra execution.
- **A mismatch** is a typed `JournalDiverged { journal (≤ 32 KiB), exit_code, cycles }`, never
  classified from text. The host re-runs the binding *and* the claim-gate limits (journal cap, DA
  size, gas) on the new journal. If all pass, it writes a new bundle version, fsyncs it, and
  re-dispatches with the new hash (budgeting a second execution); if the cycles exceed the planned
  budget it hands back; otherwise it releases. After a lock the DA check is the operator cap alone (the
  DA nonce rule handles the backlog); a store that cannot write the new version keeps the lock; the
  new version is proven on the slot that diverged.
- `WorkerCommand::Prove` gains `expect_journal_sha256` (it already carries the po2) and a file-backed
  input: the worker receives `W` as a read-only fd and hashes it, so host RAM is not charged per
  copy. `PROTOCOL_VERSION` is bumped.
- Execute reports serialized segment bytes per po2; the claim gate reserves them against free space on
  the segment filesystem across every proof that may run at once.

### 15.4 Large data

- **Phase-1 ceiling:** `[witness] max_witness_bytes`, default 32 MiB, with file-backed input; raising it
  is an operator choice bounded by RAM, disk and proving time, not by the worker frame.
- **Fused validation** (absorb each byte as consumed) is sound only for single-pass consumption that
  covers every committed byte, and only with §8.2's abort rule; a sparse or conditional model
  (mixture-of-experts, routing, early exit) absorbs only touched weights — bind the full data or use a
  whole-model vector commitment with a covered-set proof.
- **Placed segments** (ABI v2, Phase 2): the host streams content-addressed bytes (a 2 GB model) into
  `W` without passing them through the builder; retention keeps an index of placed segments over the
  content cache.
- **Late-failing validation** (a crafted witness failing on its last chunk) is wasted pre-claim work,
  bounded by the limits and admission, never a post-lock failure.
- **Proof composition** (Phase 3) for extreme sizes, with §8.3's rules.

## 16. Outcomes and local verdicts

| When | Failure | Outcome | On-chain effect |
|---|---|---|---|
| Static gate | envelope malformed or out of range; unsupported type, adapter or binding; submission form; capability not provisioned; limits above maxima; not claimable; not admitted | skip | none |
| Artifact or ELF | per §13.4 / today's ELF rules | skip | none |
| Builder | trap, fuel, memory, wall clock, non-zero return, unknown import, fetch denied or exhausted | skip | none |
| Guest | fails; cycles above the limit; journals differ across po2; draws from `sys_rand` | skip | none |
| Claim gate | journal cap, binding, DA size, gas, reservation, deadline margin, prove resources | skip | none |
| After a lock — the job | anything the submitter does through the job | **nothing** (§5.5) | none |
| After a lock — blockspace | DA stall fill; blockspace bought past the deadline | residual shared with inline jobs | release penalty or slash |
| After a lock — the miner | GPU fault, prover crash, resource limit, mis-estimated prove time, gas or RPC trouble, bundle loss | retry, salvage or release | as for inline jobs |
| Any time — governance | pause, adapter disable (anyone may `graceRelease`), verifier swap, upgrade | grace exits; watched (§5.5) | as today |

**Verdict classes:**

| Failure | Class |
|---|---|
| Envelope, range, unsupported type or class, unknown import | permanent for the job |
| Guest ELF unavailable or image-id mismatch | today's rules for ELFs |
| Builder artifact | per source (§13.4); permanent for the job once every source is bad |
| Builder deterministic failure (trap, fuel, memory, non-zero return) with no status-2 fetch | permanent for the job |
| Builder transient (an operator-side fetch failure, or the wall clock expiring while a fetch waited on the operator side; not an unanswerable request) | one jittered retry on other endpoints, then permanent; never counted against the caller |
| Builder source-lagging (a fetch the job's source answered as lacking the block or state, or naming a block above its head, with fewer than two independent endpoints of that chain agreeing and the block within the pruning horizon, §9.2) | retried with backoff (6 attempts, about 16 minutes), then permanent; never counted against the caller |
| Guest failure or binding mismatch | one jittered rebuild on other endpoints (a stale node can cause it), then permanent |
| Journals differ across po2 | permanent |
| The guest calls `sys_rand` past its runtime's own draw (`GuestUsesSysRand`, §5.4) | permanent; counted against the caller |
| Operator-side (endpoint errors, 429s, operator budget exhaustion, artifact endpoint errors) | never counted against the caller; retried |
| Post-lock witness failure | the job gets a verdict that lasts until it is terminal; tallies per caller and per (device, failure class) are persisted for 7 days from the latest; a failure counts against the caller only when an attempt of its guest ran on a device not quarantined then; a caller with 3 is not admitted; a device with failures of one class from ≥ 2 distinct callers is quarantined from new witness locks until they age out (`PAGE: WITNESS-DEVICE-QUARANTINED`), while locks already held keep proving, on another card when one can; every release of a witness lock (failure, the recovery room rule, shutdown) records the job's verdict; never feeds zkminer's host-wide stop on new programs; only same-device failures across ≥ 2 callers trigger a host-wide hold |
| Measure workers busy (the image id cannot be derived now) | deferred; never final; never counted against the caller |

Scores are keyed by `(caller)`, `(builderId, caller)` and `(programId, caller)` — never by `builderId`
or `programId` alone, so a decoy job reusing a popular builder or guest cannot throttle it for
everyone; zkminer's existing two-submitter program mark is re-keyed the same way for witness jobs.

**Requester feedback.** There is no on-chain failure reason. Requesters dry-run with `zkminer
simulate --descriptor <file> [--builder <wasm>] [--elf <elf>] [--prover <addr>] [--po2 16..22]
[--broker-config <file>]`. The descriptor file comes from `zkminer witness envelope encode
--descriptor-out`. It runs the miner's own pre-claim pipeline, after the sandbox and broker
self-tests, under the configuration's `[witness]` limits, against the requester's own endpoints,
with a throwaway retention store. It prints one JSON report:

- the outcome; for a skipped job, the verdict, its step and its retry class;
- fuel, fetches, bytes, the builder's peak memory and `|W|`;
- cycles in the `maxGuestCycles` unit and the journal per po2, judged against `maxGuestCycles` as a
  miner judges the po2s it may use (§7.1): by default at the sizes this configuration's cards prove at
  (its benchmark cache and `prover.risc0_job_po2`); when it names none, at every job po2, each on its
  own, so a job over the limit at some sizes only is reported with them (`cycleLimit`) and not
  skipped, since whether a miner serves it depends on the segment size its cards prove at; `--po2`
  names the sizes to judge at (`--po2 16..22`: every one);
- the pinned bytes and the binding's mutation check;
- the estimated fulfil DA size (from `GasPriceOracle`, else an upper bound) and this host's
  admission parameters;
- the fulfil's DA estimate against `[witness] fulfil_da_cap_bytes`;
- `notChecked`: the gates only an on-chain job can be judged by.

It runs the claim gate's DA check (`DaCapPolicy`; the backlog part is `notChecked`) and holds
`hemi-code` reads to the miner's per-job artifact budget. `notChecked` also names the builder's
availability through its `builderURIs` or a mirror (`--builder`), the ProgramRegistry's ELF
(`--elf`), and a card-derived guest-cycle maximum (unless `--max-guest-cycles` or `[witness]
max_guest_cycles` gives one). Steps and retry classes are reported by stable names. The broker runs
on a copy of the configuration with a spool of its own, never a running miner's. It exits non-zero
when a miner with that configuration would skip the job. In its on-chain modes, simulate reports a
witness job `not_served`. `--adversarial` attacks the witness and host inputs (§21.1). A dry run
seeds `sys_rand` by the public rule, as a miner does (the report's `sysRandRule`), and a prefix job
is reproduced exactly only with the real `jobId` and prover. Results are read from `JobFulfilled.publicValues`.

## 17. Admission and economics

### 17.1 Principle

Admission decides how a miner spends its own CPU, bandwidth, provider quota and disk before a lock;
it never touches stake. **The price is not a commitment before a lock:** a caller can cancel an Open
job for free and caller addresses cost nothing, so a flood costs an attacker a few hundred thousand
gas per job (about 0.1–0.3 HEMI) and a recycled deposit. Admission must not rely on attacker cost.

### 17.2 The reservation

Absolute, in HEMI wei:

```
reservation = (claim gas + fulfil gas + L1 fee of the exact fulfil, at the expected tip)
              × HEMI_PER_ETH × 1.25
            + prove cost
            + k × simulation cost / P̂(win)
```

- `callbackGasLimit` is included only when `callbackContract` has code at the head, priced at the
  expected fulfil tip; the fee ceiling only sets the funding check (balance ≥ gas limit × ceiling per
  pending fulfil).
- `HEMI_PER_ETH` is operator-set with an expiry of at most 31 days, never read from an on-chain pool.
  Witness serving refuses to start while it is unset and stops admitting when it expires (`PAGE:
  RATE-EXPIRED`; held locks continue). zkminer's existing `token_price_usd` default is not used for
  witness admission.
- Simulation cost is priced in HEMI by operator unit prices: per CPU-second (builder wall time
  including compilation, plus guest execution), per GiB-hour retained, per provider overage unit.
  Quota inside a flat provider plan is capacity, allocated by lanes, not a price.
- `k` (default 1.5) is the share of the margin a host is willing to spend on simulation; the published
  reference cost model tells requesters they fund about N simulations per job. Phase 1 sets
  P̂(win) = 1 for exclusivity jobs and allowlisted callers' jobs; open-market estimation is Phase 2
  (§17.5).
- `min_profit_threshold` stays as an extra gate.

### 17.3 Lanes

Simulation capacity is divided into lanes, measured in slot-seconds and provider units:

1. **Held-lock work**, always first.
2. **Credit lane:** callers with positive credit (§17.4); Phase 2 ranks by expected value per
   slot-second.
3. **Exploration** (Phase 2, ≤ 10%): callers with credit, round-robin; its outcomes feed P̂(win).
4. **Probation:** one slot, one job per caller in flight, first-seen order. It is best-effort and can
   be flooded by fresh addresses; a requester that needs dependable service earns credit first or
   submits through a relay address that has it. A job that fails only because a probation clamp cut it
   short is deferred, not judged. Probation clamps fit a typical builder (≥ 1 MiB artifact).

**Phase 1 default: `[witness] callers` allowlist mode** — only listed callers are served, skipping
probation; open admission with lanes is an operator opt-in.

### 17.4 Credit

```
credit(caller) = c × Σ protocol fees the caller paid on fulfilled jobs (JobFulfilled.protocolFee, HEMI)
               − Σ k × simulation cost of the caller's jobs that failed simulation or were cancelled
                   after it
```

Positive credit serves the caller from the credit lane; at zero it returns to probation. Fees are
public, so one payment grants credit at every miner: `c ≤ 1/N_expected` (default 0.05), re-derived
when an adapter's fee rate changes. The threshold is in HEMI, never a job count (a job count is
farmable with 1-HEMI self-fulfilled jobs). A scan signature (§14.6) debits credit.

### 17.5 Statistics (Phase 2 open admission)

- Race statistics and stop rules are kept per caller and per `(builderId, caller)`, never per profile
  (a requester who is also a miner could otherwise poison a profile with cheap self-claims).
- A profile-level prior for P̂(win) uses only jobs of callers with credit, weighted by their fee spend,
  and never a job locked within one block of becoming claimable.
- Cold start: P̂(win) is the share of comparable public jobs (same profile key, nearby price and
  limits) that nobody locked within this host's simulation time after they became claimable, read
  from `JobSubmitted`/`JobClaimed` logs without simulating.

### 17.6 Resource isolation

- Simulation runs in its own cgroup (§10.2): low `cpu.weight`, a cpuset excluding the cores that feed
  provers, `memory.max` charged against the dispatcher's host-RAM reservation; it is skipped when the
  reservation does not fit and preempted by proving.
- The chain client gets priority lanes: held-lock reads and sends, then lock transactions, then
  pre-claim reads under a per-tick budget (default ≤ 25% of `max_requests_per_sec`), each charged to
  the caller's lane. Deployment constants (adapter `SELECTOR()`, oracle parameters) are cached per
  block.
- Jitter applies to retries and backoff only: a start delay costs only the miner that adds it.

### 17.7 Costs to expect

For the Phase-1 profile (`sc.storage` / `sc.event`) simulation is cheap — about 100 provider compute
units and seconds of execution per job — and proof windows and rate limits bind before cost does. AI
profiles (Appendix A) are dominated by weight bytes and retention.

## 18. zkminer integration

Where the design lands in the code (names, not line numbers). Phase 2 items are marked.

**Pre-claim path**

- **Measurement identity is the job.** Every pre-claim cache and dedup in `run.rs` (measured cycles,
  journal length, measure strikes, the in-flight sets, the descriptor-to-input resolver, the
  unsatisfiable-binding mark) is keyed on `keccak256(inputData)` or `descriptorHash` today. For witness
  jobs: key results by `(backend, po2, programId, sha256(prefix ‖ W))`; resolve each job to its input
  by `jobId`; key the in-flight map by `jobId` (single flight); drop the per-input dedup and the
  cross-descriptor short-circuit; re-key `measured_binding_verdict`. The claim gate and the prove
  dispatch read `J`, `W` and the po2 set from the published bundle, never from an in-memory cache.
- **One `guest_input(job, W, prover)`** used by the measure path, the lifecycle's prove dispatch, lock
  recovery and `zkminer simulate`; lift the three journal-prefix refusals in `run.rs` (inspector,
  lifecycle, measure) for risc0's `0xffffffff` only. A partial change (prefix on the measure input but
  not the prove input) would pass the gate and fail with `JournalPrefixMismatch` after the lock.
- **Payload screens.** Every screen that sizes the claim, measure, lifecycle or fulfil payload must use
  the fulfil path actually sent (`fulfillJobHashed`) and the real journal; the measure-path screen that
  uses the guest-input length would otherwise mark every `W` over 128 KiB unmeasurable.
- **Static gates:** the claimability `eth_call` (§5.3); the submission-form check; the deployment pin
  check; capability provisioning; host maxima.
- **Admission** (§17): lanes, the credit ledger, the reservation formula, allowlist mode; simulation
  and retention terms in the cost model; witness jobs require `claim_predicate_jobs`; `run
  --watch-only` never runs builders; builder failures never feed program-level cooldowns.
- **Unserved witness jobs** (no runtime, serving off, risc0 switched off, caller not admitted,
  journal-bound jobs off, a verdict that holds, a caller over its post-lock limit) are set aside in the Open set like an
  unclaimable inline job (ranked last, out of the per-tick cut): for the verdict's remaining time,
  else 10 minutes (60 s while serving is merely off), so tagged jobs cannot crowd out inline ones.
- **Lost races** classified as same-block or earlier, per caller; an optional private or
  sequencer-direct submission path for open witness-job locks.
- **Governance watchers:** `VerifierSwitchProposed` (a pending swap's `readyAt` bounds a held lock's
  proving budget and every fulfil attempt), `UpgradeProposed`,
  `BidSubmitted` (abort), router/Registry `Paused` and adapter disables (hold). zkminer has no
  verifier-swap watcher today.

**New processes**

- The sandbox launcher (§10.2) and `zkminer witness setup` (§10.3), with the startup and hourly
  self-test (the sandbox self-test on its own thread; a serving start that failed is retried with the
  hourly self-tests; the execute worker's build is asked at start and hourly).
- The **builder runner** (CPU-only wasmtime binary), the **execute worker** (CPU-only risc0 executor
  under the same sandbox profile, given the seed the miner derives by the public rule), and the **broker** (own uid;
  `evm-rpc/v1`, `blob/v1`, the `hemi-code` reader, caches, redaction).
- Hardening that applies to the whole miner: `PR_SET_DUMPABLE(0)`, `RLIMIT_CORE=0`, secret environment
  bytes scrubbed in place before `remove_var`.

**Lock and prove path**

- The **retention store** (§15): identity record and lock, bundles and versions, pins, eviction after
  the first full recovery scan, persisted verdicts; the store is the authoritative index for recovery;
  the lock journal references bundles.
- **Witness locks are immune to program-wide marks:** the lifecycle and recovery take the ELF,
  descriptor, po2 set and journals from the bundle; `program_vkey_mismatched_for` and the
  unsatisfiable-binding mark never skip or release a held witness lock; every lock's ELF is pinned in
  the store from claim intent to a terminal state (replacing the task-scoped `ElfPin`); held-lock reads
  use reserved lanes in the chain client and the broker.
- **Prove = execute, compare, prove** (§15.3): `WorkerCommand::Prove` gains `expect_journal_sha256`
  and a file-backed input; the `JournalDiverged` response variant; `segment_path` under the
  operator's segment root; a `PROTOCOL_VERSION` bump. Witness locks prove only at an executed po2
  (today's fallbacks to unmeasured sizes, including po2 20 for a recovered lock with no recorded
  sizes, do not apply to them).
- **Fulfil:** `fulfillJobHashed`, added to the selector pin list in `deployment.rs`; DA estimation
  through `GasPriceOracle` (zkminer has none today); the DA cap and the DA nonce rule — a detector for
  pending-but-unmined transactions and safe-head lag, and replacement of a stuck large fulfil by a
  minimal self-transfer at its nonce. zkminer's 10M-gas minimum on every fulfil lowers what a blocker
  must fill to hold a fulfil out; worth revisiting.
- **Post-lock failure accounting** per caller and per (device, failure class); witness failures never
  feed the host-wide new-program stop.
- `descriptor_carries_revert_lever` is unchanged: it governs how reverts are blamed in the breaker,
  which witness jobs do not affect.
- **Deployment:** a `KnownDeployment` (with its core pins) for the `3bc441dd8` stack; witness jobs only
  on a verified deployment.
- **Version bumps:** the worker protocol and the lock-journal format.

**Tools and UI**

- `zkminer simulate --descriptor` (`pipeline::simulate_witness_job`, with `JobInput::artifact` for a
  local builder and `pipeline::host_maxima` shared with the runtime) and `--adversarial`
  (`zkminer_witness_host::adversarial`: generic mutations, a `SchemeMutator` registry keyed by
  scheme id with scheme 1 from `hemiprove_eth_prelude::scheme1`, `pipeline::execute_once` for every
  re-execution, and a differential run per provider). Mutations are made just before they run
  (repeats found by sha256), scheme 1's standard set enumerated lazily; the attack refuses a `W`
  above `--adversarial-max-w-bytes` (8 MiB). `manifest::ArtifactBudget` is shared by the miner,
  simulate and the publisher.
- Requester tooling: `zkminer witness envelope encode|decode`, `zkminer witness binding
  compute|check`.
- `zkminer artifact publish` (§13.5), `--verify-rpc-url`, `--progress`, its JSON-RPC through
  `GuardedClient::post_json`.
- TUI: a Simulating state and the counters of §20.3.
- Phase 2: traced descriptor recovery for jobs submitted through a contract (scores then keyed by
  `(builderId, caller, tx.from)`, since one bad user of a shared requester contract would otherwise
  degrade its other users); competitive bidding; `hemi-code` Custom entries in
  `programs.rs::download_elf` (which gains the artifact reader).

## 19. Configuration reference

New sections reject unknown keys, and the effective witness configuration is logged at startup.
Endpoints, provider keys, the artifact endpoint, egress rules and capability configurations live in
the **broker's own config file** (`[broker] config`), which the broker reads (keys included) and the
miner's connector reads for its endpoints only (never the keys); the miner's config holds no provider
key. The rows marked *(broker file)* below are keys of that file.

| Key | Default | Meaning |
|---|---|---|
| `[witness] enabled` | `false` | Master switch; hot-toggling off stops admission and aborts simulations, keeping held locks |
| `[witness] sandbox_mode` | `"system"` | `"system"` (namespaces, separate uid, nftables floor) or `"rootless"` (Landlock + seccomp + cgroup, no kernel egress floor; §10.3) |
| `[witness] callers` | `[]` | Allowlisted callers (Phase-1 admission mode) |
| `[witness] open_admission` | `false` | Serve non-allowlisted callers through the lanes of §17.3 |
| `[witness] builders` | `"any"` | `"attested"` serves only builder ids signed in the builder registry |
| `[witness] max_witness_bytes` | 32 MiB | Host maximum for `maxWitnessBytes` |
| `[witness] max_guest_cycles` | host-derived | Host maximum for `maxGuestCycles`: the sized cycles one proof attempt can prove within `proving_timeout_secs` at the slowest eligible card's rate and the safety margin, after its fixed allowance; at most an hour of proving |
| `[witness] builder_clamps` | fuel, 512 MiB memory, 120 s, fetch counts and bytes | Clamps for builder-side limits (hard ceilings: 1 GiB, 300 s) |
| `[witness] probation_clamps` | ≥ 1 MiB artifact, 30 s | Clamps for probation callers |
| `[witness] fulfil_da_cap_bytes` | 2,048 | Estimated DA bytes of the fulfil (max about 8,500) |
| `[witness] da_backlog_hold_bytes` | 2,500,000 | Above this backlog, use the live per-transaction cap or skip |
| `[witness] hemi_per_eth`, `hemi_per_eth_expires` | required | Exchange rate and expiry (≤ 31 days) |
| `[witness] k` | 1.5 | Simulation-cost multiplier in the reservation |
| `[witness] unit_prices` | required | HEMI per CPU-second, per GiB-hour retained, per provider overage unit |
| `[witness] credit_c` | 0.05 | Credit per HEMI of protocol fees paid |
| `[witness] copy_rate_threshold` | 0.5 | Same-block loss rate above which a caller's open jobs are not simulated |
| `[witness] prover_address` | — | Non-secret; lets `artifact publish` refuse the prover key |
| `[retention] dir`, `store_uuid` | required | Retention store (own filesystem recommended) and its UUID from `zkminer witness init-store`; a store is never created implicitly |
| `[retention] quota`, `per_caller`, `free_floor` | 20 GiB, 2 GiB, 5% | Store limits |
| `[retention] segment_dir` | required | Segment scratch for proving (non-tmpfs) |
| `[artifacts] rpc_url` *(broker file)* | unset (`hemi-code` ignored) | Artifact endpoint |
| `[artifacts] max_requests_per_sec` *(broker file)* | 2 | Artifact endpoint limiter |
| `[artifacts] max_builder_bytes` *(broker file)* | 4 MiB | Maximum builder artifact size (published) |
| `[artifacts] mirror` *(broker file)* | unset | Operator mirror template, `…/{type}/{id}` |
| `[artifacts] egress_proxy` *(broker file)* | unset | Phase 2: requester URLs skipped while unset |
| `[broker] config` | required | The broker's config file: endpoints, roles, provider keys, DNS, egress (read by the broker, with keys, and by the miner's connector, endpoints only — never keys) |
| `cidrs` per endpoint, `[egress] deny_cidrs`, `[dns] servers` *(broker file)* | `[]` | Explicit operator endpoint ranges (needed for local or LAN nodes); extra denied ranges; the broker's resolvers |
| `[budget] inflight_bytes`, `held_lock_share` *(broker file)* | 256 MiB, 0.25 | Global in-flight byte budget and the share reserved for held-lock work |
| `chain_rpc_host` *(broker file)* | required | The host of the miner's `[chain] rpc_url` (§11.1): the broker refuses endpoints on it, and the miner refuses to start a broker whose file names another host (developer mode: a warning) |
| `[[evm_rpc]]` *(broker file)* | — | Per endpoint: `alias`, `url`, `chain_id`, `archive`, `max_proof_age`, `method_sets`, rates, key file |
| `[[blob_mirror]]` *(broker file)* | — | Mirror URL templates (`{sha256}`) |
| `[chain] preclaim_read_share` | 0.25 | Share of the chain limiter for pre-claim reads |
| `[dev] private_network` | `false` | Developer setting: lets job-influenced connections (ELF downloads, builder fetches, artifact reads, operator endpoints) reach non-public addresses. For local test networks only; needs `[dev] chain_id`; refused on Hemi mainnet; the miner passes it to the broker it launches (the broker file has no such key) |
| `[dev] chain_id` | unset | The chain developer mode is meant for; must equal `[chain] chain_id` (which the RPC confirms) |
| `[egress] internal_ranges` | unset | Refused like deny CIDRs; required in public mode on a host with a global IPv4 interface address or an uplink that is not plainly physical (§14), judged at startup and again on every change; `[]` states there are none |
| `[egress] ipv6_site_prefix_len`, `ipv4_site_prefix_len` | 32 (16..=64), 16 (8..=32) | Sites refused around the host's own global addresses |
| `[egress] public_addresses`, `discover_public_addresses` | `[]`, `true` | The host's public addresses; unknown on a routed family ⇒ nothing goes out over it; discovery off needs an address per routed family. Discovery confirms by the HTTPS reflector, or by both DNS reflectors unless the HTTPS reflector was answered by an impostor; a confirmation lasts 10 minutes and belongs to the uplink it was made on |
| `[egress] near_hop_limit` | 2 (2..=16) | Hop limit of the probe sent right before each connection under the floor, with a check connection when the probe gets no answer |
| `[egress] doh_resolvers` | Cloudflare, Google, Quad9 | DNS-over-HTTPS resolvers for requester names: https URLs with a public IP-literal host |
| `[witness] builder_binary`, `execute_binary`, `execute_memory_bytes`; `[broker] binary`, `memory_bytes` | next to `zkminer`; 10 GiB; 1 GiB | Sandboxed binaries and their memory caps |

## 20. Operations

### 20.1 Enabling witness jobs

1. Run `zkminer witness setup` (system install or rootless, §10.3) and apply what it prints.
2. Create the retention and segment filesystems (or set quotas and floors) and configure them.
3. Configure the artifact endpoint: the operator's own Hemi node, or a provider that does not carry
   the miner's chain traffic.
4. Provision capabilities: for `evm-rpc/v1` on a chain, an own node or a provider account under the
   operator's control that serves historical proofs at least `max_proof_age_served` deep.
5. Set `hemi_per_eth` with an expiry and the unit prices.
6. List callers (Phase-1 allowlist mode).
7. Enable, confirm the self-test passes, and dry-run a known-good witness job with `zkminer simulate`.

### 20.2 Pages

`RATE-UNSET` / `RATE-EXPIRED`; `WITNESS-DISABLED` (self-test failed); `RETENTION-LOW` (80% of quota —
a full store silently stops locks); `RETENTION-UNAVAILABLE`; `BUNDLE-MISSING`; `JOURNAL-DIVERGED`;
`ARTIFACT-ENDPOINT` (wrong chain id, lag, pruned state); `WITNESS-DEVICE-QUARANTINED`;
`WITNESS-BROKER-CUT-OFF` (the broker broke the connector protocol); `JOURNAL-UNUSABLE` (held locks only); `PROVIDER-QUOTA`; `PROBATION-STARVED`;
`COPY-RATE`; `CHAIN-RPC-STARVED` (held-lock read latency high while simulations run); for the
publisher, `PENDING-UNMINED` and `BACKLOG-WAIT`.

### 20.3 Counters

zkminer has no metrics exporter; these are structured log events and TUI counters, per lane and per
caller: simulated, passed, locked, won, lost same-block, lost earlier, failed by class, slot-seconds,
provider units, retention bytes.

### 20.4 Runbook items

- Renew `hemi_per_eth` at least monthly.
- **An unusable lock journal** (unreadable, or from a newer release) is left as it is: the miner
  drives held locks only, writes its journal beside the file, and takes no new claim until restarted
  with a usable journal (`PAGE: JOURNAL-UNUSABLE`).
- **Host migration:** drain witness locks, or move the retention store together with the lock journal;
  never start a new host against an old journal without its store.
- **Sizing:** retention ≥ concurrent simulations × `max_witness_bytes` + held locks × `|W|`; segment
  disk ≥ the largest concurrent proofs' segment bytes.
- **Kill switch:** set `[witness] enabled = false` (hot: the configuration file is read again every
  15 s): no new admissions, running simulations aborted, held locks continue, serving stays off;
  `true` again resumes after the self-tests for a miner started with serving enabled, else after a
  restart.
- Releasing undrained witness locks at shutdown records their jobs' verdicts: this host will not lock
  those jobs again until they are terminal. Drain witness locks before a planned restart.
- Never downgrade below a witness-capable release while witness locks are held.
- On a wasmtime or cranelift advisory: patch within the service-level target, or switch witness serving
  off.

## 21. Rollout, deliverables and testing

### 21.1 Phase-1 deliverables

1. **zkminer:** §18's Phase-1 items.
2. **Builder SDK:** Rust for `wasm32-unknown-unknown` with a pinned target-feature list; the ABI
   bindings; a JSON-RPC client over `fetch`; RLP encoders for headers and receipts (feature `eth`,
   from the reference prelude). A builder that shares crates with its guest keeps them inside the
   builder workspace's directory (the SDK's `reference` symlink): a path dependency outside it keeps
   its absolute path in the module's panic locations, which changes the module's bytes from one
   checkout to the next. Build one builder per invocation (feature unification changes bytes).
3. **Requester tooling:** an envelope encoder; a FIELDS / `expectedJournalHash` calculator that works
   from the requester's parameters; an automated mutation check; `zkminer simulate --descriptor`;
   `zkminer simulate --adversarial`, which attacks the witness, not only the binding:
   - the verdict is `fail` unless the binding pins `[0, H)` with a non-zero `expectedJournalHash`;
   - per-scheme structured mutations first: scheme 1 flips node and header bytes, drops or appends
     nodes, swaps in the parent or the next block's header (fetched through the job's `evm-rpc`
     source), swaps another slot's proof, swaps inclusion for exclusion and reorders leaves;
   - then generic mutations of any `W`: sampled byte flips, truncation, trailing bytes, and the
     drop, duplication and reordering of items in every length-delimited framing `W` parses as.

   Each mutation must fail in the guest, give a byte-identical journal, or change bytes the binding
   pins (the router refuses it). A changed journal that still satisfies the binding is reported as a
   soundness failure naming the mutation. Each mutation runs under this host's cycle maximum, not
   the job's `maxGuestCycles` (the router does not check cycles); a run stopped at the host maximum
   is inconclusive (under FULL it decides nothing). Differential runs go against two providers, each
   alone in its own broker; different journals that both satisfy the binding are a soundness
   failure. Re-execution runs under two `sys_rand` seeds (the public rule's and a fresh random one), two po2s (each in a request of its own, the
   second from `--po2`, a cycle cap reported as such) and two keccak po2s, and any journal change is
   reported as a dependence on a prover-controlled host input. These checks compare journals only,
   which cannot show a check of `W` that follows the seed while the journal does not (a spot check
   at a drawn index); that is caught by the execute's count of the guest's `sys_rand` calls (§5.4),
   which skips such a job before any attack and marks a host-input pair dependent wherever a run
   draws. All of this runs within a time bound
   and writes a JSON report whose verdict is `pass`, `fail` or `incomplete`. Every execute and
   broker start gets what is left of the time bound and is killed there. A stale-proof swap is not
   made: a scheme-1 `W` names no keys to fetch. The last tool is `zkminer artifact publish`.
4. **Reference guest library:** audited `eth-block` state, receipt and transaction modules with the
   `Pinned` / `Authenticated` types of §8.3, plus lints banning default-seeded `HashMap`/`HashSet`,
   `env::exit`/`pause`, `env::var`/`args`, `cycle_count`, `sys_rand`, raw `sys_keccak`, the raw
   syscall entry points (`syscall_*`, `SYS_*` names, `asm!`, `send_recv`), fds other than stdin
   (`FdReader`, `sys_read` of another fd), and `static`/`thread_local!`/`Cell`/`RefCell` in guests.
   Three layers: clippy, the built ELF (the `ecall`, caller and name-string rules), and a source
   scan. Every risc0 guest's runtime draws memory-image entropy through `sys_rand` in `env::init`,
   which never reaches the journal; the check allows that one caller and no other. **No mainnet
   serving until audited.**
5. A reference builder and guest for §12: `sdk/examples/proxy-slots`, `reference/proxy-slots`.
6. The contracts-repo documentation (§7.3).

### 21.2 Phases and gates

- **Phase 1:** type-1 builders from the cache, an operator mirror or `hemi-code`; `evm-rpc/v1`
  (`state-read`) and `blob/v1`; risc0 guests; FULL and FIELDS bindings (already served for inline
  jobs) plus the journal-prefix marker (new in the miner path); exclusivity-window jobs recommended;
  allowlist admission by default; `fulfillJobHashed`, the DA gate and nonce rule; the retention store
  and execute-compare-prove; `W` ≤ 32 MiB; top-level submissions; the `sc.storage` / `sc.event`
  profile.
- **Phase 2:** `https`/`ipfs` builder URIs through the artifact egress; the ELF fetch behind the broker
  (with its migration) and `hemi-code` ELFs; type-2 and type-3 builders; placed segments; `ipfs/v1`,
  `btc-rpc/v1` (policy enforced by the broker's typed re-encoding, `rpcwhitelist` only a second
  layer), `https-pool/v1`; `state-trace`; SP1 witness jobs (prefix buffer, proof nonce, a pre-claim
  vkey check, proven public values compared with `J`, an executor-equivalence argument); competitive
  bidding; open admission with expected-value ranking and P̂(win); traced descriptor recovery; witness
  reuse keyed by `keccak256(abi.encode(BuilderContextV1))`.
- **Phase 3:** native builders in a microVM; Tier-2 requester content; proof composition.
- **Gates:** 743111 first, with the caller allowlist and exclusivity jobs; the kill switch available
  from day one. Before open admission or mainnet: zero post-lock releases caused by job content across
  N witness locks; same-block copy rate, probation wait times and the publisher's peak backlog
  contribution measured; a red-team sign-off of the sandbox and broker; the prelude audit.

### 21.3 Test and acceptance plan

- **Unit and fuzz:** strict envelope decode and re-encode; locator parsing; manifest checks; the
  broker's typed decode (case-variant and duplicate keys, the `debug_setHead` smuggle) and canonical
  re-emission; the allow-only-global predicate and floor rules; budget accounting; the reservation
  formula; bundle write, verify and versioning; store state transitions.
- **Sandbox:** unknown imports; memory, fuel, table and compilation bombs; features outside the
  profile (threads, atomics, SIMD) rejected; seccomp denials; no network or filesystem in the builder;
  fd passing; every negative case of the self-test.
- **Adversarial:** DNS rebinding; decompression bombs; slow upstreams; decoy manifests and builder ids;
  a po2-sensitive guest; a `sys_rand`-reading guest; a sibling envelope riding another job's
  measurement; journal divergence at prove time; the retention store unmounted at boot; deletion
  racing a re-lock; a fulfil stranded by the DA throttle.
- **Localnet:** extend `tests/localnet.rs` with a second anvil as the `evm-rpc` chain and the artifact
  endpoint; GPU tests run with `--test-threads=1`.
- **Testnet end to end on 743111:** publish a builder with `hemi-code`, submit an exclusivity job, lock,
  fulfil, read `JobFulfilled.publicValues`.
- **Acceptance:** the §21.2 gates.

## 22. Open questions

- Does Hemi offer private or sequencer-direct transaction submission, to blunt copied locks on open
  jobs?
- Should competitive bidding move into Phase 1?
- How do requesters discover which miners provision a capability (chain, `maxProofAge`, `hemi-code`)?
  An unprovisioned job otherwise stays Open with no signal; optional unsigned per-job verdict telemetry
  could help.
- Admission defaults: unit prices, `k`, the rotation share, probation clamps, `credit_c` against the
  number of miners.
- Should publisher thresholds be derived from the guardian's configured backlog thresholds rather than
  constants?
- Retention limits for very large witnesses, and proving from disk.
- The operator mirror protocol (how mirrors are populated and addressed).
- Variable-size journals under any aggregation layer.
- Scheme and prelude versioning (guest-library versioning): the scheme-1 `W` carries a format
  version byte (1); the prelude is 0.1.0, unaudited; how attestations name the prelude version
  linked into a guest is open.
- Whether to require the journal-prefix marker on every open witness job.
- Recording Hemi's fork level and its EIP-6780 / EIP-7702 chain confirmations.
- Permanent state growth on Hemi from `hemi-code` publishing.

---

## Appendix A — Beyond Phase 1: profiles

### A.1 Core and profiles

The core (§5.7) knows nothing about any domain. A **profile** bundles, for one use case: schemes, an
audited prelude (§8), a capability template (§11), a builder template, a cost model for admission
(§17), and an attestation binding them. A profile may only compose core primitives, never grant a
capability the core withholds (an egress exemption, a method outside the frozen lists, key access, a
lock before simulation). Requester guidance no miner can enforce: the binding pins the scheme id, the
commitment and every question-defining parameter (§7.2, §8.2).

### A.2 Registries (off-chain)

Scheme registry (id → semantics, preimage layout, reference prelude); capability-class registry (class
id → config schema, request format, frozen method list, caps, cost weights, with a spec hash published
next to each name-addressed class id); builder-type registry (ABI versions); profile registry. Meaning
is pinned only by the guest (`programId`) and the binding; versions named in an envelope affect only
how honest miners build `W`.

### A.3 AI inference

`content-merkle` over weights with an injective encoding (§8.3); dense models fuse on consumption,
sparse ones (mixture-of-experts, routing, early exit) need a whole-model vector commitment with a
covered-set proof; every read authenticated (autoregressive decoding re-verifies or keeps weights
verified in memory); **sampling is greedy or seeded from a seed pinned in the header and expanded in
the guest, never from `sys_rand`**; quantization, rounding and accumulation order fixed by the
requester (in-guest soft-float is deterministic; the recipe is what must be pinned); tokenizer and
preprocessing committed; base + adapter as two sub-witnesses; batched inference binds each
input→output pair; property proofs reveal a predicate, never input privacy against provers. Needs
placed segments (Phase 2); cost is dominated by weight bytes and retention.

### A.4 Blockchain state transitions, multi-chain

EVM/MPT (assert every header root, §8.1), Tendermint/Cosmos, Bitcoin/UTXO (anchor rules §8.5, txid
malleability §8.3), Solana and others. Anchoring per §8.5; multi-block ranges are walked backward from
a pinned end; access discovery is builder logic, completeness is guest logic (§8.4).

### A.5 Smart-contract-targeted proofs (the Phase-1 profile)

`sc.storage` (MPT verification only, §8.4); `sc.event` (receipt-trie proofs, which log pinned or
re-derived, §8.2, §8.4); `sc.call` (one read-only call with the pinned call context and fork rules of
§8.4); multi-read (a bounded set of reads on one chain composed into one statement); ERC helpers
(attested preludes for common layouts: ERC20 balances, ERC721 owners, EIP-1967); historical state
subject to `maxProofAge`.

### A.6 The long tail

Data availability (a proof shows the prover held matching bytes when proving, not that they remain
retrievable); dataset queries (bind the dataset root, not only touched rows); TLS-notarized web (the
attestation binds the server name, method, path, query, any identity the response depends on, and the
time); oracle aggregation (§8.1's distinct-signer and fixed-input-set rules); credentials. Most need
Phase-2 capabilities.

### A.7 Multi-source composition

A vector of named sub-witnesses, each with its own scheme, capability and sub-commitment
(`commitment := merkleRoot({ name_i : (scheme_i, commitment_i) })`); sub-commitments independent and
domain-separated; the statement binds the linkage it claims ("the state root the model consumed == the
block's state root"); each chain anchored per §8.5 (Base's own canonicality needs anchor 1 from a
finalized head or the L1 route); one builder may assemble all sub-witnesses within per-capability
budgets.

### A.8 Advanced cryptography

Hiding commitments (privacy toward the public, never toward provers); KZG vector commitments (a
declared trusted-setup assumption); accumulators; recursive aggregation (`env::verify`, constant image
ids). The first release uses keccak, SHA-256 and Merkle trees only.

### A.9 Per-profile economics

All local (§17): a profile's cost model maps declared limits (fetches, cost units, bytes, fuel,
slot-seconds, guest cycles, retention) to simulation and prove cost; requesters price against the
same published model. No bond, no on-chain reputation, no on-chain floor.

## Appendix B — `hemi-code` publishing cost

- **Gas per chunk:** 21,000 + 32,000 (creation) + 16 per calldata byte + 200 per byte of code deposit
  (+ about 2 per initcode word): about 5.0M for a 23,000-byte chunk, about 5.4M for a full
  24,575-byte one. 1 MiB is 46 chunks and about 231M gas, plus the manifest. EIP-7623's calldata floor
  does not bind (the code deposit dominates).
- **L2 gas:** at a tip near the inclusion floor (about 10 wei) plus a base fee of about 252 wei, about
  6 × 10⁻⁸ ETH per MiB — negligible; at a 0.01 gwei tip, about 0.0023 ETH per MiB.
- **L1 data fee:** linear in Ethereum's base fee (`baseFeeScalar` 1e6, blob scalar 0): 16 × the L1
  base fee per estimated byte, at about 0.86 estimated bytes per incompressible byte — about
  0.0009 ETH per MiB at 0.062 gwei, about 0.4 ETH per MiB at 30 gwei; negligible on the testnet.
- **DA estimate:** the Fjord estimate, 0.8365 × FastLZ size − 42.6 (minimum 100); a 23,000-byte
  incompressible chunk transaction estimates at about 19,900 bytes.
- **Throughput:** under the 250 KB backlog rule, with batches posted about every 5 minutes, about
  20 minutes per MiB.
