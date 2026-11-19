//! The compile-cost budget (plan §9.1): a bound on Cranelift's work, computed by the pre-pass in its
//! one streaming pass, before anything is compiled.
//!
//! Compilation runs before any fuel is consumed, and the structural limits (body size, locals per
//! function, functions per module) do not bound it: Cranelift's cost grows superlinearly with shapes
//! a small module can have. Measured with this runner's [`engine_config`](crate::engine::engine_config)
//! (`OptLevel::None`, wasmtime 48.0.8, release build of the runner) on the reference host (x86_64,
//! 2026-11-16), one compile at a time:
//!
//! | Shape | Cost per unit | Unit |
//! |---|---|---|
//! | nested loops reading locals | 1.8–2.1 ns, ~0 bytes | (max loop depth + 1) × locals², per function |
//! | nested `if`/`else` | 7.4–11 ns, ~6 bytes | control depth², per function |
//! | joins (branch targets) before locals are read | 88–145 ns, 30–45 bytes | branch targets × locals, per function |
//! | declared locals | 87–89 ns | locals (params included) |
//! | function types (trampolines) | ≤ 41 ns | (params + results)², per distinct type |
//! | defined functions | 77 µs, ~6 KiB | functions |
//!
//! "Locals" counts a function's params and declared locals; "branch targets" counts `br`, `br_if`,
//! `if`, and every `br_table` target including the default. Memory is per function (Cranelift frees
//! a function's context before the next), except the ~6 KiB each compiled function keeps.
//!
//! # The budget
//!
//! The pre-pass prices each term at the upper end of its measured cost ([`CompileCost::estimate_ns`])
//! and refuses a module whose estimate is over [`COMPILE_BUDGET_NS`] (2 s on the reference host).
//! One budget for all the terms means a module that spends several of them at once still stays
//! within it. Next to it, hard caps bound what the budget does not: [`MAX_CONTROL_DEPTH`] and
//! [`MAX_FUNCTION_BRANCH_LOCALS`] the memory of one function, [`MAX_TYPE_ARITY`] and [`MAX_TYPES`] the
//! type section. (Locals need no cap of their own: the "+ 1" prices a loop-free function's locals²
//! too, ~100× above its real cost, which already holds a module under ~2.3 million locals.)
//!
//! Calibration: the bombs from the runner review (time and peak RSS of `Module::from_binary`):
//!
//! | Module | Before | Now |
//! |---|---|---|
//! | 1 function, 4,096 locals read inside 64 nested loops (16.5 KB) | 1.96 s, 32 MiB | refused: estimate 2.18 s |
//! | same, 20 functions | 39.5 s | refused: estimate 43.6 s |
//! | 4,096 locals, 1,024 nested loops | 30.7 s, 356 MiB | refused: estimate 34.4 s |
//! | 4,096 locals, 5,000 / 81,957 nested loops | 156 s, 1.8 GiB / > 300 s, 9.4 GiB | refused: depth > 1,024 |
//! | 32,000 nested `if`/`else` (256 KB) | 7.6 s, 5.9 GiB | refused: depth > 1,024 |
//! | 35,124 sequential `br_if` joins × 4,096 locals | 15.9 s, 3.9 GiB | refused: 1.4e8 branch targets × locals in a function |
//! | 100,000 empty functions × 4,096 locals | 37.5 s, 597 MiB | refused: estimate 3,400 s |
//! | 100,000 empty functions, no locals | 7.7 s, 611 MiB | refused: estimate 8.0 s |
//! | 100,000 functions of 290 bytes (29 MB) | 10–24 s, 0.7–1 GiB | refused: estimate 8.0 s |
//! | 4,000 unused types × 1,000 params | 59 s | refused: arity > 128 |
//! | 10,000 distinct types × 127 params | 6.6 s, 234 MiB | refused: estimate 6.8 s |
//!
//! The largest module of each class that the pre-pass accepts:
//!
//! | Module at the edge | Estimate | Compiles in | Peak RSS |
//! |---|---|---|---|
//! | 1 function, 4,096 locals, 58 nested loops | 1.98 s | 1.78 s | 29 MiB |
//! | 1 function, 1,024 locals, 945 nested loops | 1.99 s | 2.12 s | 137 MiB |
//! | 156 functions of 1,024 nested `if`/`else` | 2.00 s | 1.95 s | 57 MiB |
//! | 1 function, 1,024 locals, 9,765 joins (the per-function cap) | 1.50 s | 0.96 s | 315 MiB |
//! | 2 functions, 256 locals, 26,000 joins each | 2.00 s | 1.75 s | 359 MiB |
//! | 2,900 distinct types × 128 params | 2.00 s | 1.89 s | 75 MiB |
//! | 24,998 empty functions | 2.00 s | 1.88 s | 157 MiB |
//! | 58 functions × 4,096 locals, no loops | 1.97 s | 0.02 s | 11 MiB |
//!
//! Real builders, by contrast (`sdk/test-builders`, release builds; LLVM reuses wasm locals, so no
//! function has more than ~110):
//!
//! | Builder | Size | Functions | Estimate | Compiles in | Max depth | Max arity | Max branch × locals in a function |
//! |---|---|---|---|---|---|---|---|
//! | `receipts-proof`, `opt-level = 3` | 378 KB | 370 | 70 ms | 0.34 s | 95 | 7 | 70,040 |
//! | `storage-proof`, `opt-level = 3` | 315 KB | 364 | 59 ms | 0.29 s | 80 | 7 | 73,636 |
//! | `receipts-proof`, `opt-level = "s"` | 275 KB | 384 | 61 ms | 0.32 s | 93 | 7 | 36,207 |
//! | `storage-proof`, `opt-level = "s"` | 230 KB | 367 | 47 ms | 0.26 s | 94 | 7 | 33,764 |
//!
//! That is ≥ 28× under the budget, 10.8× under [`MAX_CONTROL_DEPTH`] (the tightest cap: deep nesting
//! is how LLVM lowers a large `match`), 18× under [`MAX_TYPE_ARITY`], ≥ 136× under
//! [`MAX_FUNCTION_BRANCH_LOCALS`] and ≥ 450× under [`MAX_TYPES`]; `tests/realistic_builders.rs` checks
//! the 10×. Unoptimized debug builds of the same builders (11–12 MB, ~4,000 functions) estimate 434 /
//! 407 ms (4.6×) with depth up to 144 (7.1×); nobody should publish one.
//!
//! **Not bounded by the budget:** the linear cost of ordinary code, ~0.1–0.8 µs per code byte (the
//! 29 MB module above, cut to the 25,000 functions the budget allows, still has ~7 MB of code).
//! Pricing it would leave real builders far less than 10× headroom (they compile at ~0.8 µs per
//! byte); [`MAX_MODULE_BYTES`](crate::prepass::MAX_MODULE_BYTES) (≈ 30 MB), the wall clock (counted
//! from process start, with the watchdog already running) and the cgroup's `memory.max` bound it. A
//! slower host scales every figure here; the wall clock is the backstop there too.

/// Deepest control nesting (`block`, `loop`, `if`) in one function. Also bounds a nested-`if`
/// function's memory (~6 bytes × depth²: ~6 MiB at the cap). LLVM lowers a `match` to one nested
/// block per arm, so this also caps a function at ~1,000 match arms.
pub const MAX_CONTROL_DEPTH: u32 = 1_024;
/// Most params + results in one function type.
pub const MAX_TYPE_ARITY: usize = 128;
/// Most function types in the type section.
pub const MAX_TYPES: u64 = 10_000;
/// Most branch targets × locals in one function: its compile memory (30–45 bytes per unit, so
/// ≤ ~450 MiB).
pub const MAX_FUNCTION_BRANCH_LOCALS: u64 = 10_000_000;
/// The estimated compile time a module may cost, in reference-host nanoseconds.
pub const COMPILE_BUDGET_NS: u64 = 2_000_000_000;

/// The price of each budget term, in reference-host nanoseconds per unit: the upper end of what was
/// measured (see the module docs).
pub mod weight {
    /// Per defined function.
    pub const FUNCTION: u64 = 80_000;
    /// Per local (params included).
    pub const LOCAL: u64 = 90;
    /// Per (max loop depth + 1) × locals², per function.
    pub const LOOP_LOCALS_SQ: u64 = 2;
    /// Per control depth², per function.
    pub const DEPTH_SQ: u64 = 12;
    /// Per branch target × locals, per function.
    pub const BRANCH_LOCALS: u64 = 150;
    /// Per (params + results)², per function type.
    pub const TYPE_ARITY_SQ: u64 = 42;
}

/// The caps [`prepass_with_caps`](crate::prepass::prepass_with_caps) applies. The runner always uses
/// [`CostCaps::DEFAULT`]; other values are for calibration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CostCaps {
    pub budget_ns: u64,
    pub types: u64,
    pub function_branch_locals: u64,
}

impl CostCaps {
    pub const DEFAULT: Self =
        Self { budget_ns: COMPILE_BUDGET_NS, types: MAX_TYPES, function_branch_locals: MAX_FUNCTION_BRANCH_LOCALS };
    /// No budget and none of these caps (the structural limits still apply), to measure what a
    /// module would cost.
    pub const UNLIMITED: Self = Self { budget_ns: u64::MAX, types: u64::MAX, function_branch_locals: u64::MAX };
}

/// One function's shape, as the pre-pass scans its body.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct FunctionShape {
    /// Params plus declared locals.
    pub locals: u64,
    pub max_depth: u32,
    pub max_loop_depth: u32,
    pub branches: u64,
}

/// A module's compile-cost terms, as the pre-pass accumulates them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CompileCost {
    /// Defined functions (imports are not compiled).
    pub functions: u64,
    /// Function types.
    pub types: u64,
    /// Σ over types of (params + results)².
    pub type_arity_sq: u64,
    /// Σ over functions of locals (params included).
    pub locals: u64,
    /// Σ over functions of (max loop nesting depth + 1) × locals².
    pub loop_locals_sq: u64,
    /// Σ over functions of (max control nesting depth)².
    pub depth_sq: u64,
    /// Σ over functions of branch targets × locals.
    pub branch_locals: u64,
    /// The largest of these, for reports.
    pub max_type_arity: u64,
    pub max_function_locals: u64,
    pub max_depth: u32,
    pub max_loop_depth: u32,
    pub max_function_branch_locals: u64,
}

impl CompileCost {
    pub(crate) fn add_type(&mut self, arity: u64) {
        self.types += 1;
        self.type_arity_sq = self.type_arity_sq.saturating_add(arity * arity);
        self.max_type_arity = self.max_type_arity.max(arity);
    }

    pub(crate) fn add_function(&mut self, f: &FunctionShape) {
        let l = f.locals;
        let l2 = l.saturating_mul(l);
        let branch_locals = f.branches.saturating_mul(l);
        self.functions += 1;
        self.locals = self.locals.saturating_add(l);
        self.loop_locals_sq = self.loop_locals_sq.saturating_add(l2.saturating_mul(u64::from(f.max_loop_depth) + 1));
        self.depth_sq = self.depth_sq.saturating_add(u64::from(f.max_depth) * u64::from(f.max_depth));
        self.branch_locals = self.branch_locals.saturating_add(branch_locals);
        self.max_function_locals = self.max_function_locals.max(l);
        self.max_depth = self.max_depth.max(f.max_depth);
        self.max_loop_depth = self.max_loop_depth.max(f.max_loop_depth);
        self.max_function_branch_locals = self.max_function_branch_locals.max(branch_locals);
    }

    /// Each budget term's price, in reference-host nanoseconds: (name, units, nanoseconds).
    pub fn priced_terms(&self) -> [(&'static str, u64, u64); 6] {
        let t = |name, units: u64, w: u64| (name, units, units.saturating_mul(w));
        [
            t("functions", self.functions, weight::FUNCTION),
            t("locals", self.locals, weight::LOCAL),
            t("(loop depth + 1) × locals²", self.loop_locals_sq, weight::LOOP_LOCALS_SQ),
            t("control depth²", self.depth_sq, weight::DEPTH_SQ),
            t("branch targets × locals", self.branch_locals, weight::BRANCH_LOCALS),
            t("type arity²", self.type_arity_sq, weight::TYPE_ARITY_SQ),
        ]
    }

    /// The estimated compile time, in reference-host nanoseconds.
    pub fn estimate_ns(&self) -> u64 {
        self.priced_terms().iter().fold(0u64, |acc, (_, _, ns)| acc.saturating_add(*ns))
    }

    /// The first cap the module is over, as a reason.
    pub fn check(&self, caps: &CostCaps) -> Result<(), String> {
        if self.types > caps.types {
            return Err(format!("{} function types (max {})", self.types, caps.types));
        }
        if self.max_function_branch_locals > caps.function_branch_locals {
            return Err(format!(
                "a function with branch targets × locals = {} (max {})",
                self.max_function_branch_locals, caps.function_branch_locals
            ));
        }
        let estimate = self.estimate_ns();
        if estimate > caps.budget_ns {
            let (name, units, _) = self.priced_terms().into_iter().max_by_key(|t| t.2).unwrap_or(("", 0, 0));
            return Err(format!(
                "compile cost estimated at {} ms, over the budget of {} ms (largest term: {name} = {units})",
                estimate / 1_000_000,
                caps.budget_ns / 1_000_000
            ));
        }
        Ok(())
    }
}
