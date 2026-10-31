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

use wasmi::{Config, Engine, Linker, Module, Store, StoreLimitsBuilder};

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
pub const MAX_FUEL: u64 = 10_000_000_000;

/// Smallest linear memory a caller may configure: enough for the input and
/// output areas.
pub const MIN_MEMORY_BYTES: usize = 2 * OUTPUT_OFFSET;

/// Largest linear memory a caller may configure.
pub const MAX_MEMORY_BYTES: usize = 1 << 30;

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
}

impl Default for WasmLimits {
    fn default() -> Self {
        Self {
            fuel: 1_000_000,
            max_memory_bytes: 16 << 20,
            max_output_bytes: 64 << 10,
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
    /// `env.clock_ms() -> i64`: milliseconds since the Unix epoch.
    pub clock: bool,
    /// `env.random(ptr, len) -> i32`: fills guest memory from the OS CSPRNG.
    pub random: bool,
    /// `env.log(ptr, len) -> i32`: appends to a bounded host-side log.
    pub log: bool,
    /// Largest log a guest may produce in one call, in bytes.
    pub max_log_bytes: usize,
}

/// Largest log a guest may emit in one call, whatever the policy asks for.
pub const MAX_HOST_LOG: usize = 64 << 10;

/// Largest buffer `env.random` will fill in one call.
pub const MAX_HOST_RANDOM: u32 = 64 << 10;

/// The wasmi store state: the resource ceilings and the host log.
struct HostState {
    limits: wasmi::StoreLimits,
    log: Vec<u8>,
    max_log: usize,
}

/// A sandboxed guest tool.
pub struct WasmTool {
    engine: Engine,
    module: Module,
    limits: WasmLimits,
    host: WasmHostPolicy,
    /// Host log captured from the most recent call.
    log: Vec<u8>,
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
        for import in module.imports() {
            let allowed = match (import.module(), import.name()) {
                ("env", "clock_ms") => host.clock,
                ("env", "random") => host.random,
                ("env", "log") => host.log,
                _ => false,
            };
            if !allowed {
                return Err(provider("wasm/import"));
            }
        }
        Ok(WasmTool {
            engine,
            module,
            limits,
            host,
            log: Vec::new(),
        })
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
        if input.len() > OUTPUT_OFFSET {
            return Err(provider("wasm/input"));
        }
        let limits = StoreLimitsBuilder::new()
            .memory_size(self.limits.max_memory_bytes)
            .instances(1)
            .memories(1)
            .tables(4)
            .build();
        let state = HostState {
            limits,
            log: Vec::new(),
            max_log: self.host.max_log_bytes,
        };
        let mut store = Store::new(&self.engine, state);
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(self.limits.fuel)
            .map_err(|_| provider("wasm/fuel"))?;
        let mut linker = Linker::new(&self.engine);
        if self.host.clock {
            linker
                .func_wrap("env", "clock_ms", || -> i64 {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|elapsed| elapsed.as_millis() as i64)
                        .unwrap_or(0)
                })
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
                        if used + len as usize > cap {
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
        let instance = linker
            .instantiate_and_start(&mut store, &self.module)
            .map_err(|_| provider("wasm/instantiate"))?;
        let memory = instance
            .get_memory(&store, "memory")
            .ok_or_else(|| provider("wasm/memory"))?;
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
        // The declared host functions are read-only: a clock reading, CSPRNG
        // bytes and a per-call log buffer. A guest cannot change host state.
        false
    }

    fn invoke(&mut self, _object: u64, call: &Call) -> Result<Response> {
        if call.method != "run" {
            return Err(Error::MethodNotGranted {
                method: call.method.clone(),
            });
        }
        let input = call
            .args
            .iter()
            .find_map(|arg| match arg {
                Arg::Value(Value::Text(text)) => Some(text.as_bytes().to_vec()),
                Arg::Value(Value::Module(bytes)) => Some(bytes.clone()),
                _ => None,
            })
            .unwrap_or_default();
        let output = self.call(&input)?;
        // ABI v1 treats the guest output as text. Binary results should travel
        // as a module value in a future version.
        Ok(Response::Value(Value::Text(
            String::from_utf8_lossy(&output).into_owned(),
        )))
    }
}

fn provider(code: &str) -> Error {
    Error::Provider {
        code: code.to_string(),
    }
}
