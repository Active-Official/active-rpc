//! Fuel-metered WebAssembly guest tools.
//!
//! A guest runs in an interpreter with no host imports, a bounded linear
//! memory and a fuel budget. The kernel still owns authority: the tool is only
//! reachable through a minted capability, and a guest cannot reach the host at
//! all in this build — any module that declares an import is refused before it
//! runs.
//!
//! # ABI v1
//!
//! - The guest exports `memory` and `run(len: i32) -> i32`.
//! - The host writes the input at offset `0` (at most 64 KiB) and passes its
//!   length.
//! - The guest writes its output at offset `65536` and returns the output
//!   length. A negative length, or one beyond the configured ceiling, is
//!   refused.
//! - The guest must not declare imports. Host functions become available only
//!   through a future capability policy, never by default.

use crate::error::{Error, Result};
use crate::kernel::Provider;
use crate::value::{Arg, Call, Response, Value};

use wasmi::{
    Config, Engine, ExternType, FuncType, Linker, Module, Store, StoreLimitsBuilder, ValType,
};

/// Input area: the host writes the call argument here.
pub const INPUT_OFFSET: usize = 0;
/// Output area: the guest writes its result here.
pub const OUTPUT_OFFSET: usize = 64 * 1024;

/// Largest module the host compiles, in bytes.
///
/// Compilation happens before any fuel exists, so an unbounded module is an
/// unbounded allocation and an unbounded compile. One MiB is far above any
/// hand-written tool and far below a denial-of-service payload.
pub const MAX_MODULE_BYTES: usize = 1 << 20;

/// Largest fuel budget a caller may configure.
///
/// At roughly 4 000 fuel per millisecond of interpreted work on a developer
/// machine, this is a few minutes of CPU: enough for a heavy batch tool, far
/// below "a call that never returns". A capability's wall budget
/// (`Call::budget.max_wall_ms`) tightens it per call.
pub const MAX_FUEL: u64 = 1_000_000_000;

/// Fuel a guest may burn per millisecond of its wall budget.
///
/// The interpreter costs roughly 4 000 fuel per millisecond of debug-build work,
/// so this rate makes a wall budget binding (a 100 ms grant buys 500 000 fuel)
/// without throttling a fast guest. It is a proportional ceiling, not a
/// deadline: a guest that never executes an instruction cannot exceed it, and
/// the interpreter cannot outrun it by more than the measurement error.
pub const FUEL_PER_MS: u64 = 5_000;

/// Largest table a guest may declare or grow to, in elements.
///
/// A table element is a 16-byte slot, so a 1 MiB ceiling is 16 MiB of host
/// memory; without a ceiling a 140-byte module can ask for tens of gigabytes,
/// and a failed allocation aborts the process instead of returning an error.
pub const MAX_TABLE_ELEMENTS: usize = 1 << 16;

/// Smallest linear memory a caller may configure: enough for the input and
/// output areas.
pub const MIN_MEMORY_BYTES: usize = 2 * OUTPUT_OFFSET;

/// Largest linear memory a caller may configure.
pub const MAX_MEMORY_BYTES: usize = 256 << 20;

/// Recursion ceiling imposed on the engine, independent of the fuel budget.
const MAX_RECURSION_DEPTH: usize = 1_024;

/// Value-stack ceiling imposed on the engine, in bytes.
const MAX_STACK_BYTES: usize = 1 << 20;

/// Resource ceilings for a guest tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WasmLimits {
    /// Fuel the guest may consume in one call.
    pub fuel: u64,
    /// Maximum linear memory the guest may create or grow to, in bytes.
    pub max_memory_bytes: usize,
    /// Maximum output the guest may return, in bytes.
    pub max_output_bytes: usize,
    /// Maximum table the guest may declare or grow to, in elements.
    pub max_table_elements: usize,
}

impl Default for WasmLimits {
    fn default() -> Self {
        Self {
            fuel: 1_000_000,
            max_memory_bytes: 16 << 20,
            max_output_bytes: 64 << 10,
            max_table_elements: 1_024,
        }
    }
}

/// Host functions a guest may import (ABI v2).
///
/// Deny-by-default: every flag starts `false`, so a tool built without an
/// explicit policy behaves exactly like ABI v1 and a module that imports
/// anything is refused with `wasm/import`. Each granted import is a *declared*
/// host capability of that tool instance; the kernel still gates whether the
/// tool runs at all through the capability that points at it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WasmHostPolicy {
    /// `env.clock_ms() -> i64`: milliseconds from the kernel's clock.
    pub clock: bool,
    /// `env.random(ptr, len) -> i32`: fills guest memory from the OS CSPRNG.
    pub random: bool,
    /// `env.log(ptr, len) -> i32`: appends to a bounded host-side log.
    pub log: bool,
    /// Largest log a guest may produce in one call, in bytes.
    pub max_log_bytes: usize,
    /// Accept WebAssembly *text* as well as binary.
    ///
    /// Off by default: a 1 MiB text module can expand into far more compiled
    /// code than 1 MiB, and compilation happens before any fuel is charged. An
    /// embedder that compiles its own hand-written tools can turn it on for
    /// those, and must never turn it on for bytes from a peer.
    pub accept_wat: bool,
}

/// Largest log a guest may emit in one call, whatever the policy asks for.
pub const MAX_HOST_LOG: usize = 64 << 10;

/// Largest buffer `env.random` will fill in one call (per request; the call's
/// cumulative budget is [`MAX_RANDOM_PER_CALL`]).
pub const MAX_HOST_RANDOM: u32 = 64 << 10;

/// Entropy one guest call may be given in total, in bytes.
///
/// The per-request ceiling alone bounds nothing a loop cannot repeat.
pub const MAX_RANDOM_PER_CALL: usize = 64 << 10;

/// Fuel charged per KiB of linear memory the instance declares.
///
/// Instantiating a guest materialises its declared memory, and wasmi charges no
/// fuel for it: measured 5.5 ms (release) for the 16 MiB default and 90 ms for
/// the 256 MiB ceiling, under a grant of any size. At the documented rate
/// ([`FUEL_PER_MS`]) that is ~1.7 fuel per KiB; the charge is 2, so a 16 MiB
/// guest costs one millisecond of grant and the ceiling costs sixteen.
pub const FUEL_PER_MEMORY_KIB: u64 = 2;

/// The wasmi store state: the resource ceilings and the host log.
struct HostState {
    limits: wasmi::StoreLimits,
    log: Vec<u8>,
    max_log: usize,
    /// Bytes of entropy this call has been given.
    ///
    /// `MAX_HOST_RANDOM` bounds one request; without a cumulative bound a guest
    /// loops and makes the host service megabytes of CSPRNG per call, which is
    /// host work the wall grant does not pay for (measured 37 MiB in 25.6 ms
    /// under a 1 ms grant).
    random_used: usize,
    /// Cumulative entropy budget for one call, in bytes.
    max_random: usize,
}

/// A sandboxed guest tool.
pub struct WasmTool {
    engine: Engine,
    module: Module,
    limits: WasmLimits,
    host: WasmHostPolicy,
    /// Host log captured from the most recent call.
    log: Vec<u8>,
    /// Time the guest sees when the clock import is granted.
    ///
    /// Seeded by the embedder: the kernel passes `Call::now_ms`, so the guest
    /// follows the kernel's clock policy (virtual by default). A tool driven
    /// outside the kernel sees 0 until it calls [`WasmTool::set_time_ms`].
    now_ms: u64,
}

impl WasmTool {
    /// Compile a guest from WASM bytes (or WAT text, which wasmi accepts).
    ///
    /// This is the ABI v1 entry point: the host policy is deny-by-default, so
    /// any import is refused.
    pub fn from_bytes(bytes: &[u8], limits: WasmLimits) -> Result<WasmTool> {
        Self::from_bytes_with_policy(bytes, limits, WasmHostPolicy::default())
    }

    /// Compile a guest with an explicit host policy (ABI v2).
    ///
    /// Every ceiling is validated before anything is allocated or compiled. A
    /// module may import only the functions the policy grants; anything else is
    /// refused before instantiation, so a guest can never reach a host function
    /// the embedder did not declare.
    pub fn from_bytes_with_policy(
        bytes: &[u8],
        limits: WasmLimits,
        mut host: WasmHostPolicy,
    ) -> Result<WasmTool> {
        if bytes.is_empty() || bytes.len() > MAX_MODULE_BYTES {
            return Err(provider("wasm/module"));
        }
        // Text modules expand far beyond their own size during compilation, and
        // compilation happens before any fuel exists. Only an embedder that
        // compiles its own tools may feed text.
        if !host.accept_wat && !bytes.starts_with(b"\0asm") {
            return Err(provider("wasm/module"));
        }
        if limits.fuel == 0 || limits.fuel > MAX_FUEL {
            return Err(provider("wasm/limits"));
        }
        if limits.max_memory_bytes < MIN_MEMORY_BYTES || limits.max_memory_bytes > MAX_MEMORY_BYTES
        {
            return Err(provider("wasm/limits"));
        }
        if limits.max_output_bytes == 0 || limits.max_output_bytes > OUTPUT_OFFSET {
            return Err(provider("wasm/limits"));
        }
        if limits.max_table_elements == 0 || limits.max_table_elements > MAX_TABLE_ELEMENTS {
            return Err(provider("wasm/limits"));
        }
        if host.max_log_bytes > MAX_HOST_LOG {
            return Err(provider("wasm/limits"));
        }
        if !host.log {
            host.max_log_bytes = 0;
        }
        let mut config = Config::default();
        config.consume_fuel(true);
        // A recursive guest must trap on the engine's depth ceiling instead of
        // exhausting the host stack while it still has fuel.
        config.set_max_recursion_depth(MAX_RECURSION_DEPTH);
        config.set_max_stack_height(MAX_STACK_BYTES);
        let engine = Engine::new(&config);
        let module = Module::new(&engine, bytes).map_err(|_| provider("wasm/module"))?;
        // The policy is about *functions*: an import with a granted name but the
        // wrong kind or signature is not a granted import, and accepting it
        // would rest the guarantee on the linker's own resolution instead of on
        // this check.
        for import in module.imports() {
            let expected = match (import.module(), import.name()) {
                ("env", "clock_ms") if host.clock => Some(FuncType::new([], [ValType::I64])),
                ("env", "random") if host.random => {
                    Some(FuncType::new([ValType::I32, ValType::I32], [ValType::I32]))
                }
                ("env", "log") if host.log => {
                    Some(FuncType::new([ValType::I32, ValType::I32], [ValType::I32]))
                }
                _ => None,
            };
            match (expected, import.ty()) {
                (Some(expected), ExternType::Func(actual)) if actual == &expected => {}
                _ => return Err(provider("wasm/import")),
            }
        }
        Ok(WasmTool {
            engine,
            module,
            limits,
            host,
            log: Vec::new(),
            now_ms: 0,
        })
    }

    /// Seed the time the clock import reports.
    ///
    /// The kernel does this per call from `Call::now_ms`; an embedder that runs
    /// a tool outside the kernel sets it explicitly, so the guest never reads
    /// the operating system's clock behind the kernel's back.
    pub fn set_time_ms(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
    }

    /// The time the clock import currently reports.
    pub fn time_ms(&self) -> u64 {
        self.now_ms
    }

    /// The limits this tool enforces.
    pub fn limits(&self) -> WasmLimits {
        self.limits
    }

    /// The host policy this tool was built with.
    pub fn host_policy(&self) -> WasmHostPolicy {
        self.host
    }

    /// The log the guest produced during the most recent call.
    pub fn log(&self) -> &[u8] {
        &self.log
    }

    /// Take the log produced during the most recent call.
    pub fn take_log(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.log)
    }

    /// Run the guest on `input` and return its output.
    pub fn call(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        // Every refusal below must leave no log behind: `log()` is documented as
        // this call's evidence, and a stale buffer would attribute one caller's
        // bytes to another caller's failed call.
        self.log.clear();
        if input.len() > OUTPUT_OFFSET {
            return Err(provider("wasm/input"));
        }
        let limits = StoreLimitsBuilder::new()
            .memory_size(self.limits.max_memory_bytes)
            .table_elements(self.limits.max_table_elements)
            .instances(1)
            .memories(1)
            .tables(4)
            .build();
        let state = HostState {
            limits,
            log: Vec::new(),
            max_log: self.host.max_log_bytes,
            random_used: 0,
            max_random: MAX_RANDOM_PER_CALL,
        };
        let mut store = Store::new(&self.engine, state);
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(self.limits.fuel)
            .map_err(|_| provider("wasm/fuel"))?;
        let mut linker = Linker::new(&self.engine);
        if self.host.clock {
            // The kernel's clock, not the operating system's: a guest that can
            // read real time breaks replay determinism and gets a covert channel
            // the kernel claims not to have. The embedder seeds it
            // (`set_time_ms`, or `Call::now_ms` through the kernel).
            let now = self.now_ms as i64;
            linker
                .func_wrap("env", "clock_ms", move || -> i64 { now })
                .map_err(|_| provider("wasm/import"))?;
        }
        if self.host.random {
            linker
                .func_wrap(
                    "env",
                    "random",
                    |mut caller: wasmi::Caller<'_, HostState>, ptr: u32, len: u32| -> i32 {
                        if len > MAX_HOST_RANDOM {
                            return -1;
                        }
                        // One request is bounded, and so is the call: a guest
                        // that loops would otherwise make the host work far past
                        // the wall grant it paid for.
                        let used = caller.data().random_used;
                        if used.saturating_add(len as usize) > caller.data().max_random {
                            return -1;
                        }
                        caller.data_mut().random_used = used.saturating_add(len as usize);
                        let Some(memory) = caller
                            .get_export("memory")
                            .and_then(|export| export.into_memory())
                        else {
                            return -1;
                        };
                        let mut buffer = vec![0u8; len as usize];
                        if getrandom::fill(&mut buffer).is_err() {
                            return -1;
                        }
                        let data = memory.data_mut(&mut caller);
                        let start = ptr as usize;
                        let Some(end) = start.checked_add(buffer.len()) else {
                            return -1;
                        };
                        if end > data.len() {
                            return -1;
                        }
                        data[start..end].copy_from_slice(&buffer);
                        0
                    },
                )
                .map_err(|_| provider("wasm/import"))?;
        }
        if self.host.log {
            linker
                .func_wrap(
                    "env",
                    "log",
                    |mut caller: wasmi::Caller<'_, HostState>, ptr: u32, len: u32| -> i32 {
                        let cap = caller.data().max_log;
                        let used = caller.data().log.len();
                        // Saturating: a hostile 32-bit `len` must not wrap the
                        // comparison into a pass.
                        if used.saturating_add(len as usize) > cap {
                            return -1;
                        }
                        let Some(memory) = caller
                            .get_export("memory")
                            .and_then(|export| export.into_memory())
                        else {
                            return -1;
                        };
                        let data = memory.data(&caller);
                        let start = ptr as usize;
                        let Some(end) = start.checked_add(len as usize) else {
                            return -1;
                        };
                        if end > data.len() {
                            return -1;
                        }
                        let chunk = data[start..end].to_vec();
                        caller.data_mut().log.extend_from_slice(&chunk);
                        0
                    },
                )
                .map_err(|_| provider("wasm/import"))?;
        }
        // A start function that traps keeps its log: the log is diagnostic
        // evidence (ADR-0019), not a success signal.
        let instance = match linker.instantiate_and_start(&mut store, &self.module) {
            Ok(instance) => instance,
            Err(error) => {
                self.log = std::mem::take(&mut store.data_mut().log);
                return Err(classify_instantiation(error));
            }
        };
        let memory = match instance.get_memory(&store, "memory") {
            Some(memory) => memory,
            None => {
                self.log = std::mem::take(&mut store.data_mut().log);
                return Err(provider("wasm/memory"));
            }
        };
        // The instance's declared memory was just materialised; charge it before
        // the guest can spend its whole grant on allocations it never pays for.
        let memory_kib = (memory.data_size(&store) as u64).div_ceil(1024);
        let memory_fuel = memory_kib.saturating_mul(FUEL_PER_MEMORY_KIB);
        let remaining = store.get_fuel().unwrap_or(0);
        if memory_fuel > remaining {
            self.log = std::mem::take(&mut store.data_mut().log);
            return Err(provider("wasm/limits"));
        }
        store
            .set_fuel(remaining - memory_fuel)
            .map_err(|_| provider("wasm/fuel"))?;
        {
            let data = memory.data_mut(&mut store);
            if data.len() < input.len() {
                return Err(provider("wasm/memory"));
            }
            data[INPUT_OFFSET..INPUT_OFFSET + input.len()].copy_from_slice(input);
        }
        let run = instance
            .get_typed_func::<i32, i32>(&store, "run")
            .map_err(|_| provider("wasm/entry"))?;
        let returned = match run.call(&mut store, input.len() as i32) {
            Ok(value) => value,
            Err(error) => {
                // Keep whatever the guest logged before it trapped: the log is
                // diagnostic evidence, not a success signal.
                self.log = std::mem::take(&mut store.data_mut().log);
                // wasmi reports an exhausted budget as an out-of-fuel trap.
                let out_of_fuel = error.as_trap_code() == Some(wasmi::TrapCode::OutOfFuel)
                    || matches!(error.kind(), wasmi::errors::ErrorKind::Fuel(_));
                return Err(provider(if out_of_fuel {
                    "wasm/fuel"
                } else {
                    "wasm/trap"
                }));
            }
        };
        self.log = std::mem::take(&mut store.data_mut().log);
        if returned < 0 {
            return Err(provider("wasm/output"));
        }
        let output_len = returned as usize;
        if output_len > self.limits.max_output_bytes {
            return Err(provider("wasm/output"));
        }
        let data = memory.data(&store);
        if data.len() < OUTPUT_OFFSET + output_len {
            return Err(provider("wasm/memory"));
        }
        Ok(data[OUTPUT_OFFSET..OUTPUT_OFFSET + output_len].to_vec())
    }
}

impl std::fmt::Debug for WasmTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmTool")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl Provider for WasmTool {
    fn name(&self) -> &'static str {
        "wasm"
    }

    fn methods(&self) -> Vec<String> {
        vec!["run".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        // A run mutates this tool: the guest log is provider state and a guest
        // can spend fuel, allocate memory and read a clock. Reporting "no" would
        // let a read-only capability run third-party code.
        true
    }

    fn invoke(&mut self, _object: u64, call: &Call) -> Result<Response> {
        // Every refusal below returns before the child tool (and its cleared
        // log) exists, so the previous call's bytes would be attributed to this
        // one. The kernel-facing path is the one an operator reads.
        self.log.clear();
        if call.method != "run" {
            return Err(Error::MethodNotGranted {
                method: call.method.clone(),
            });
        }
        // Exactly one input, and nothing else: dropping arguments silently would
        // let a caller believe the guest processed data it never saw, and a
        // payload this adapter does not consume must not disappear either.
        if !call.payload.is_empty() {
            return Err(Error::InvalidArgument(
                "the wasm adapter reads its input from a single argument, not a payload",
            ));
        }
        let mut input = None;
        for arg in &call.args {
            let bytes = match arg {
                Arg::Value(Value::Text(text)) => Some(text.as_bytes().to_vec()),
                Arg::Value(Value::Module(bytes)) => Some(bytes.clone()),
                _ => None,
            };
            if input.is_some() || bytes.is_none() {
                return Err(Error::InvalidArgument(
                    "the wasm adapter takes exactly one text or module argument",
                ));
            }
            input = bytes;
        }
        let Some(input) = input else {
            return Err(Error::InvalidArgument(
                "the wasm adapter takes exactly one text or module argument",
            ));
        };

        // The call's wall budget bounds the guest: fuel is a proxy for CPU time,
        // and a capability that granted 100 ms must not buy minutes of
        // interpretation because the tool's default fuel is generous.
        let granted = call.budget.max_wall_ms.saturating_mul(FUEL_PER_MS);
        let fuel = self.limits.fuel.min(granted);
        if fuel == 0 {
            return Err(Error::BudgetExceeded("wall"));
        }
        let mut limits = self.limits;
        limits.fuel = fuel;
        let mut tool = WasmTool {
            engine: self.engine.clone(),
            module: self.module.clone(),
            limits,
            host: self.host,
            log: Vec::new(),
            now_ms: call.now_ms,
        };
        let result = tool.call(&input);
        // Keep the guest's log even when the call was refused: a trap is exactly
        // when its diagnostics matter, and `call` cleared the buffer first so it
        // can only hold this call's bytes.
        self.log = std::mem::take(&mut tool.log);
        let output = result?;
        // Guest output is bytes: a lossy UTF-8 conversion would hand the caller
        // text the guest never produced. Binary results travel as a module value.
        if std::str::from_utf8(&output).is_ok() {
            Ok(Response::Value(Value::Text(
                String::from_utf8(output).expect("checked above"),
            )))
        } else {
            Ok(Response::Module(output))
        }
    }
}

fn provider(code: &str) -> Error {
    Error::Provider {
        code: code.to_string(),
    }
}

/// Classify an instantiation failure.
///
/// The `start` function runs out of the same fuel pool as `run`, so an
/// out-of-fuel trap there is a budget refusal, not a malformed module; a link
/// or type failure is an import-policy refusal; a resource-limit refusal is a
/// limits refusal. Anything else stays `wasm/instantiate`.
fn classify_instantiation(error: wasmi::Error) -> Error {
    let out_of_fuel = error.as_trap_code() == Some(wasmi::TrapCode::OutOfFuel)
        || matches!(error.kind(), wasmi::errors::ErrorKind::Fuel(_));
    if out_of_fuel {
        return provider("wasm/fuel");
    }
    // A trap raised by the start function is the guest's fault, not a malformed
    // module: the caller retries `wasm/instantiate` (a module it can fix) and
    // reports `wasm/trap` (a guest that failed), so mapping the two together
    // looped.
    if error.as_trap_code().is_some() {
        return provider("wasm/trap");
    }
    match error.kind() {
        wasmi::errors::ErrorKind::Linker(_) => provider("wasm/import"),
        wasmi::errors::ErrorKind::Instantiation(
            wasmi::errors::InstantiationError::TooManyInstances
            | wasmi::errors::InstantiationError::TooManyTables
            | wasmi::errors::InstantiationError::TooManyMemories
            | wasmi::errors::InstantiationError::FailedToInstantiateMemory(_)
            | wasmi::errors::InstantiationError::FailedToInstantiateTable(_)
            | wasmi::errors::InstantiationError::ElementSegmentDoesNotFit { .. },
        ) => provider("wasm/limits"),
        wasmi::errors::ErrorKind::Memory(_) | wasmi::errors::ErrorKind::Table(_) => {
            provider("wasm/limits")
        }
        wasmi::errors::ErrorKind::Instantiation(_) => provider("wasm/import"),
        _ => provider("wasm/instantiate"),
    }
}
