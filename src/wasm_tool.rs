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

/// A sandboxed guest tool.
pub struct WasmTool {
    engine: Engine,
    module: Module,
    limits: WasmLimits,
}

impl WasmTool {
    /// Compile a guest from WASM bytes (or WAT text, which wasmi accepts).
    pub fn from_bytes(bytes: &[u8], limits: WasmLimits) -> Result<WasmTool> {
        // Every ceiling is validated before anything is allocated or compiled.
        // A zero fuel budget or a zero output area would fail open (nothing to
        // charge, nothing to bound), so they are configuration errors rather
        // than surprises at call time.
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
        let mut config = Config::default();
        config.consume_fuel(true);
        // A recursive guest must trap on the engine's depth ceiling instead of
        // exhausting the host stack while it still has fuel.
        config.set_max_recursion_depth(MAX_RECURSION_DEPTH);
        config.set_max_stack_height(MAX_STACK_BYTES);
        let engine = Engine::new(&config);
        let module = Module::new(&engine, bytes).map_err(|_| provider("wasm/module"))?;
        // No host imports in ABI v1: anything the guest asks for is refused
        // before instantiation, so a capability can never silently widen into a
        // host function.
        if module.imports().next().is_some() {
            return Err(provider("wasm/import"));
        }
        Ok(WasmTool {
            engine,
            module,
            limits,
        })
    }

    /// The limits this tool enforces.
    pub fn limits(&self) -> WasmLimits {
        self.limits
    }

    /// Run the guest on `input` and return its output.
    pub fn call(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        if input.len() > OUTPUT_OFFSET {
            return Err(provider("wasm/input"));
        }
        let store_limits = StoreLimitsBuilder::new()
            .memory_size(self.limits.max_memory_bytes)
            .instances(1)
            .memories(1)
            .tables(4)
            .build();
        let mut store = Store::new(&self.engine, store_limits);
        store.limiter(|state| state);
        store
            .set_fuel(self.limits.fuel)
            .map_err(|_| provider("wasm/fuel"))?;
        let linker = Linker::new(&self.engine);
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
        // The guest has no host imports, so it cannot mutate host state.
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
