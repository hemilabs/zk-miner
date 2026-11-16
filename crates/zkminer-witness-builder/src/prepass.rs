//! The streaming pre-pass (plan §9.1): one wasmparser pass over the module, before any compilation,
//! that validates it against exactly the ABI v1 profile and rejects shapes that are cheap to write
//! and expensive to compile or instantiate.
//!
//! A module the pre-pass rejects never reaches cranelift. Every rejection is [`exit::INVALID_MODULE`]
//! except an import outside `hemiprove_builder_v1`'s six functions, which is [`exit::UNKNOWN_IMPORT`].
//!
//! Order of the checks, which decides the exit code of a module with several faults: sections are
//! checked as they stream in (so an unknown import is reported before a later invalid function body),
//! and the required exports are checked at the end.

use wasmparser::types::{CoreTypeId, EntityType, TypesRef};
use wasmparser::{
    CompositeInnerType, ElementItems, FuncType, FunctionBody, Operator, Parser, Payload, TypeRef, ValType,
    ValidPayload, Validator, WasmFeatures,
};
use zkminer_witness::{abi, ipc::exit};

/// The ABI v1 WASM profile (plan §9.1): MVP (with floats), mutable globals, sign-extension,
/// saturating float-to-int, bulk memory, multi-value, and reference types for `funcref` only (which
/// brings the overlong `call_indirect` encoding current Rust emits). `GC_TYPES` is off, so `externref`
/// and every other non-`funcref` reference type is rejected. Everything else is off: SIMD (fixed and
/// relaxed), threads and atomics, multi-memory, memory64, exceptions, tail calls, GC, function
/// references, extended-const, the component model, custom page sizes, wide arithmetic, stack
/// switching.
pub const PROFILE_FEATURES: WasmFeatures = WasmFeatures::FLOATS
    .union(WasmFeatures::MUTABLE_GLOBAL)
    .union(WasmFeatures::SIGN_EXTENSION)
    .union(WasmFeatures::SATURATING_FLOAT_TO_INT)
    .union(WasmFeatures::BULK_MEMORY)
    .union(WasmFeatures::MULTI_VALUE)
    .union(WasmFeatures::REFERENCE_TYPES);

/// Largest module the runner accepts: the largest artifact a `hemi-code` manifest can describe.
pub const MAX_MODULE_BYTES: usize =
    zkminer_witness::manifest::MAX_MANIFEST_CHUNKS as usize * zkminer_witness::manifest::MAX_CHUNK_BODY;
/// Largest function body, in bytes (its encoded size, locals included).
pub const MAX_FUNCTION_BODY_BYTES: usize = 256 * 1024;
/// Most declared locals in one function (parameters are capped separately, at 1,000, by wasmparser).
pub const MAX_LOCALS: u64 = 4_096;
/// Most functions, imported and defined together.
pub const MAX_FUNCTIONS: u64 = 100_000;
/// Most targets in one `br_table` (the default target not counted).
pub const MAX_BR_TABLE_TARGETS: u32 = 65_536;
/// Most elements in the table, at instantiation and after any `table.grow`; also the most element
/// items across all element segments.
pub const MAX_TABLE_ELEMENTS: u64 = 65_536;

const WASM_PAGE_BYTES: u64 = 65_536;

/// Why the pre-pass rejected a module.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrepassError {
    /// Malformed, outside the profile, or over a pre-pass limit: [`exit::INVALID_MODULE`].
    #[error("invalid module: {0}")]
    Invalid(String),
    /// An import that is not one of the six ABI v1 functions with its exact signature:
    /// [`exit::UNKNOWN_IMPORT`].
    #[error("unknown import: {0}")]
    UnknownImport(String),
}

impl PrepassError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Invalid(_) => exit::INVALID_MODULE,
            Self::UnknownImport(_) => exit::UNKNOWN_IMPORT,
        }
    }
}

/// What the pre-pass learned about an accepted module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleInfo {
    /// `(module, name)` of every import, in order (all `hemiprove_builder_v1` functions).
    pub imports: Vec<(String, String)>,
    /// Imported plus defined functions.
    pub functions: u64,
    /// The memory's initial size in bytes.
    pub initial_memory_bytes: u64,
}

fn invalid(msg: impl Into<String>) -> PrepassError {
    PrepassError::Invalid(msg.into())
}

fn wasm_err(e: wasmparser::BinaryReaderError) -> PrepassError {
    PrepassError::Invalid(e.to_string())
}

/// The signature each ABI v1 import must have, as (params, results).
pub fn import_signature(name: &str) -> Option<(&'static [ValType], &'static [ValType])> {
    use ValType::{I32, I64};
    Some(match name {
        abi::IMPORT_INPUT_LEN => (&[], &[I32]),
        abi::IMPORT_INPUT_READ => (&[I32, I32, I32], &[I32]),
        abi::IMPORT_FETCH => (&[I32, I32, I32], &[I64]),
        abi::IMPORT_RESPONSE_READ => (&[I32, I32, I32], &[I32]),
        abi::IMPORT_WITNESS_WRITE => (&[I32, I32], &[I32]),
        abi::IMPORT_LOG => (&[I32, I32], &[]),
        _ => return None,
    })
}

fn func_type<'a>(types: &'a TypesRef<'_>, id: CoreTypeId) -> Option<&'a FuncType> {
    match &types[id].composite_type.inner {
        CompositeInnerType::Func(f) => Some(f),
        _ => None,
    }
}

fn check_import(types: &TypesRef<'_>, module: &str, name: &str, ty: Option<EntityType>) -> Result<(), PrepassError> {
    let unknown = || PrepassError::UnknownImport(format!("{module}::{name}"));
    if module != abi::MODULE {
        return Err(unknown());
    }
    let (params, results) = import_signature(name).ok_or_else(unknown)?;
    let Some(EntityType::Func(id)) = ty else {
        return Err(PrepassError::UnknownImport(format!("{module}::{name} is not a function")));
    };
    let f = func_type(types, id).ok_or_else(unknown)?;
    if f.params() != params || f.results() != results {
        return Err(PrepassError::UnknownImport(format!("{module}::{name} has the wrong signature {f}")));
    }
    Ok(())
}

/// Scans a body for the limits wasmparser does not enforce at our sizes, before validating it.
fn check_body(body: &FunctionBody<'_>) -> Result<(), PrepassError> {
    let size = body.range().len();
    if size > MAX_FUNCTION_BODY_BYTES {
        return Err(invalid(format!("function body of {size} bytes (max {MAX_FUNCTION_BODY_BYTES})")));
    }
    let mut locals = 0u64;
    for decl in body.get_locals_reader().map_err(wasm_err)? {
        let (count, _) = decl.map_err(wasm_err)?;
        locals += u64::from(count);
        if locals > MAX_LOCALS {
            return Err(invalid(format!("more than {MAX_LOCALS} locals in one function")));
        }
    }
    let mut ops = body.get_operators_reader().map_err(wasm_err)?;
    while !ops.eof() {
        if let Operator::BrTable { targets } = ops.read().map_err(wasm_err)? {
            if targets.len() > MAX_BR_TABLE_TARGETS {
                return Err(invalid(format!("br_table with {} targets (max {MAX_BR_TABLE_TARGETS})", targets.len())));
            }
        }
    }
    Ok(())
}

/// Runs the pre-pass. `memory_clamp_bytes` is the effective `maxBuilderMemoryBytes`.
pub fn prepass(module: &[u8], memory_clamp_bytes: u64) -> Result<ModuleInfo, PrepassError> {
    if module.len() > MAX_MODULE_BYTES {
        return Err(invalid(format!("module of {} bytes (max {MAX_MODULE_BYTES})", module.len())));
    }
    let mut validator = Validator::new_with_features(PROFILE_FEATURES);
    let mut allocs = wasmparser::FuncValidatorAllocations::default();
    let mut imports = Vec::new();
    let mut imported_funcs = 0u64;
    let mut functions = 0u64;
    let mut memories = 0u32;
    let mut tables = 0u32;
    let mut initial_memory_bytes = 0u64;
    let mut data_bytes = 0u64;
    let mut element_items = 0u64;

    for payload in Parser::new(0).parse_all(module) {
        let payload = payload.map_err(wasm_err)?;
        // Function bodies are size-checked and scanned before the validator touches them.
        if let Payload::CodeSectionEntry(body) = &payload {
            check_body(body)?;
        }
        let valid = validator.payload(&payload).map_err(wasm_err)?;
        match &payload {
            Payload::ImportSection(reader) => {
                let types = validator.types(0).ok_or_else(|| invalid("no module types"))?;
                for import in reader.clone().into_imports() {
                    let import = import.map_err(wasm_err)?;
                    check_import(&types, import.module, import.name, types.entity_type_from_import(&import))?;
                    match import.ty {
                        TypeRef::Func(_) | TypeRef::FuncExact(_) => imported_funcs += 1,
                        TypeRef::Memory(_) => memories += 1,
                        TypeRef::Table(_) => tables += 1,
                        TypeRef::Global(_) | TypeRef::Tag(_) => {}
                    }
                    imports.push((import.module.to_string(), import.name.to_string()));
                }
                if imported_funcs > MAX_FUNCTIONS {
                    return Err(invalid(format!("more than {MAX_FUNCTIONS} functions")));
                }
            }
            Payload::FunctionSection(reader) => {
                functions = imported_funcs + u64::from(reader.count());
                if functions > MAX_FUNCTIONS {
                    return Err(invalid(format!("{functions} functions (max {MAX_FUNCTIONS})")));
                }
            }
            Payload::MemorySection(reader) => {
                for mem in reader.clone() {
                    let mem = mem.map_err(wasm_err)?;
                    memories += 1;
                    if memories > 1 {
                        return Err(invalid("more than one memory"));
                    }
                    if mem.memory64 {
                        return Err(invalid("memory64"));
                    }
                    if mem.shared {
                        return Err(invalid("shared memory"));
                    }
                    initial_memory_bytes = mem.initial.saturating_mul(WASM_PAGE_BYTES);
                    if initial_memory_bytes > memory_clamp_bytes {
                        return Err(invalid(format!(
                            "initial memory of {initial_memory_bytes} bytes is above the clamp {memory_clamp_bytes}"
                        )));
                    }
                }
            }
            Payload::TableSection(reader) => {
                for table in reader.clone() {
                    let table = table.map_err(wasm_err)?;
                    tables += 1;
                    if tables > 1 {
                        return Err(invalid("more than one table"));
                    }
                    if table.ty.table64 {
                        return Err(invalid("table64"));
                    }
                    if table.ty.initial > MAX_TABLE_ELEMENTS {
                        return Err(invalid(format!(
                            "table of {} elements (max {MAX_TABLE_ELEMENTS})",
                            table.ty.initial
                        )));
                    }
                }
            }
            Payload::DataSection(reader) => {
                for data in reader.clone() {
                    let len = data.map_err(wasm_err)?.data.len() as u64;
                    data_bytes += len;
                    if len > memory_clamp_bytes || data_bytes > memory_clamp_bytes {
                        return Err(invalid(format!(
                            "data segments of {data_bytes} bytes do not fit the memory clamp {memory_clamp_bytes}"
                        )));
                    }
                }
            }
            Payload::ElementSection(reader) => {
                for elem in reader.clone() {
                    let items = match elem.map_err(wasm_err)?.items {
                        ElementItems::Functions(r) => r.count(),
                        ElementItems::Expressions(_, r) => r.count(),
                    };
                    element_items += u64::from(items);
                    if element_items > MAX_TABLE_ELEMENTS {
                        return Err(invalid(format!("more than {MAX_TABLE_ELEMENTS} element segment items")));
                    }
                }
            }
            _ => {}
        }
        match valid {
            ValidPayload::Func(func, body) => {
                let mut fv = func.into_validator(std::mem::take(&mut allocs));
                fv.validate(&body).map_err(wasm_err)?;
                allocs = fv.into_allocations();
            }
            ValidPayload::End(types) => {
                check_exports(&types.as_ref())?;
                return Ok(ModuleInfo { imports, functions, initial_memory_bytes });
            }
            ValidPayload::Parser(_) => return Err(invalid("nested modules and components")),
            ValidPayload::Ok => {}
        }
    }
    Err(invalid("truncated module"))
}

/// The required exports: `memory` (32-bit) and `run: () -> i32`. Any other export is tolerated and
/// ignored: Rust's wasm32 cdylibs export the globals `__heap_base` and `__data_end`, and nothing can
/// call an export the runner does not.
fn check_exports(types: &TypesRef<'_>) -> Result<(), PrepassError> {
    let exports = types.core_exports().ok_or_else(|| invalid("not a core module"))?;
    let (mut memory, mut run) = (false, false);
    for (name, ty) in exports {
        match (name, ty) {
            (abi::EXPORT_MEMORY, EntityType::Memory(m)) if !m.memory64 => memory = true,
            (abi::EXPORT_MEMORY, _) => return Err(invalid("export `memory` is not a 32-bit memory")),
            (abi::EXPORT_RUN, EntityType::Func(id)) => {
                let ok = func_type(types, id).is_some_and(|f| f.params().is_empty() && f.results() == [ValType::I32]);
                if !ok {
                    return Err(invalid("export `run` is not a function () -> i32"));
                }
                run = true;
            }
            (abi::EXPORT_RUN, _) => return Err(invalid("export `run` is not a function () -> i32")),
            _ => {}
        }
    }
    if !memory {
        return Err(invalid("missing export `memory`"));
    }
    if !run {
        return Err(invalid("missing export `run`"));
    }
    Ok(())
}
