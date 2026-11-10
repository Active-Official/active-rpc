//! Fuel-metered WebAssembly guest tools.
//!
//! A guest runs in an interpreter with a bounded linear memory and a fuel
//! budget, and every call is bounded by a real wall-clock deadline as well
//! as by fuel (RPC-37): fuel is the instruction bound, the deadline is the
//! wall bound, and the deadline is enforced by a clock around the
//! execution. Compilation is bounded the same way (RPC-39): it runs before
//! any fuel exists, so the text input is capped before parsing and the
//! compile itself runs on a worker thread under a wall deadline, or the
//! caller would be held for the full compile time of a hostile module.
//! The kernel still owns authority: the tool is only reachable through
//! a minted capability. Host imports are deny-by-default: a module that declares
//! an import the build's WasmHostPolicy does not explicitly grant is refused
//! before it runs, and a granted one is a single checked host function
//! (clock, random, log), never a general host ABI.
//!
//! # ABI v1
//!
//! - The guest exports `memory` and `run(len: i32) -> i32`.
//! - The host writes the input at offset `0` (at most 64 KiB) and passes its
//!   length.
//! - The guest writes its output at offset `65536` and returns the output
//!   length. A negative length, or one beyond the configured ceiling, is
//!   refused.
//! - The guest must not declare an import that WasmHostPolicy does not grant;
//!   a granted import is one of the checked host functions, never a general ABI.

use crate::error::{Error, Result};
use crate::kernel::Provider;
use crate::value::{Arg, Call, Response, Value};

use std::time::Duration;

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
/// hand-written tool and far below a denial-of-service payload. The compile
/// itself is bounded by a wall deadline as well as by this ceiling
/// ([`MAX_COMPILE_WALL`], RPC-39): the ceiling bounds the work, the
/// deadline bounds the wall time even on a machine where the work runs
/// far slower than the rate predicts.
pub const MAX_MODULE_BYTES: usize = 1 << 20;

/// Largest WebAssembly *text* the host parses, in bytes.
///
/// Text expands far beyond its own size during compilation — a 1 MiB text
/// module held the caller thread for ~1.1 s with no deadline anywhere
/// (RPC-39) — so text is capped far below the binary ceiling, *before*
/// parsing. 64 KiB is far above any hand-written tool (every WAT fixture
/// in this repo is under 1 KiB) and bounds the worst text compile to
/// ~70 ms on the fix machine. Anything that is not binary module bytes and
/// is past this cap is refused with `wasm/module` before a byte of it is
/// parsed.
pub const MAX_WAT_BYTES: usize = 64 << 10;

/// Longest a compile may hold the caller, in wall time.
///
/// Compilation runs before any fuel exists, so neither the fuel meter nor
/// the call deadline (RPC-37) reaches it — both bound execution, and the
/// module does not exist yet. A compile that outlives this deadline is
/// refused with `wasm/timeout` instead of holding the caller. Five seconds
/// is one default call's wall grant (`Budget::default().max_wall_ms`) and
/// 16x the worst legitimate compile measured on the fix machine (a binary
/// just under the 1 MiB ceiling compiles in ~311 ms in debug; the worst
/// text compile under [`MAX_WAT_BYTES`] is ~70 ms), so a legitimate module
/// has ample headroom in either build while a hostile one is still cut
/// off in seconds.
pub const MAX_COMPILE_WALL: Duration = Duration::from_secs(5);

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
/// so this rate converts a wall budget into a fuel budget (a 100 ms grant buys
/// 500 000 fuel) without throttling a fast guest, and converts a fuel budget
/// back into the wall deadline a direct [`WasmTool::call`] enforces. It is a
/// conversion rate, not a deadline: on a slow or loaded machine the same fuel
/// takes far longer than the rate predicts, so the rate alone never bound a
/// call's wall time (RPC-37). The wall deadline is enforced by a real clock
/// around the guest's execution ([`WasmTool::call_with_deadline`]); fuel stays
/// the instruction bound and the wall clock is the additional bound.
pub const FUEL_PER_MS: u64 = 5_000;

/// Largest table a guest may declare or grow to, in elements.
///
/// A table element is a slot in the engine's element array; at 16 bytes each,
/// the 65 536-element ceiling is about 1 MiB per table, and the store limiter's
/// four-table budget bounds one call at about 4 MiB. Without a ceiling a
/// 140-byte module can ask for tens of gigabytes, and a failed allocation aborts
/// the process instead of returning an error.
///
/// Table memory is bounded by the limiter but is **not** fuel-charged the way
/// linear memory is: a module's declared tables cannot be enumerated through the
/// engine's public API, so the reservation cannot see them. The bound is the
/// limiter's, and it is small (R-14 round 3, L-4).
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
    /// those, and must never turn it on for bytes from a peer. Text that is
    /// accepted is still capped at [`MAX_WAT_BYTES`] before parsing and the
    /// compile still runs under [`MAX_COMPILE_WALL`] (RPC-39).
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
/// fuel for *instantiation*: measured 5.5 ms (release) for the 16 MiB default
/// and 90 ms for the 256 MiB ceiling, under a grant of any size. A `memory.grow`
/// inside `run` is a different path — the engine debits that one — which is why
/// this reservation covers the declaration only. At the documented rate
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
    /// Cumulative entropy a *child* call inherits, in bytes.
    ///
    /// [`MAX_RANDOM_PER_CALL`] by default; `invoke` builds the child with the
    /// capability's byte share instead, so a tiny grant cannot buy 64 KiB of
    /// CSPRNG (round 29, F6). A direct [`WasmTool::call`] keeps this ceiling.
    random_cap: usize,
    /// Entropy the last call drew, for the grant accounting in `invoke`.
    last_random_used: usize,
    /// Time the guest sees when the clock import is granted.
    ///
    /// Seeded by the embedder: the kernel passes `Call::now_ms`, so the guest
    /// follows the kernel's clock policy (virtual by default). A tool driven
    /// outside the kernel sees 0 until it calls [`WasmTool::set_time_ms`].
    now_ms: u64,
}

impl WasmTool {
    /// Compile a guest from WASM bytes.
    ///
    /// WAT text is accepted only by a policy that opts in (WasmHostPolicy::accept_wat);
    /// this entry point uses the deny-by-default policy, which refuses anything
    /// that does not start with the wasm magic. The compile runs under the
    /// default wall deadline ([`MAX_COMPILE_WALL`], RPC-39); use
    /// [`WasmTool::from_bytes_with_policy_and_deadline`] to set it explicitly.
    pub fn from_bytes(bytes: &[u8], limits: WasmLimits) -> Result<WasmTool> {
        Self::from_bytes_with_policy(bytes, limits, WasmHostPolicy::default())
    }

    /// Compile a guest with an explicit host policy (ABI v2).
    ///
    /// Every ceiling is validated before anything is allocated or compiled. A
    /// module may import only the functions the policy grants; anything else is
    /// refused before instantiation, so a guest can never reach a host function
    /// the embedder did not declare. The compile runs under the default wall
    /// deadline ([`MAX_COMPILE_WALL`], RPC-39); use
    /// [`WasmTool::from_bytes_with_policy_and_deadline`] to set it explicitly.
    pub fn from_bytes_with_policy(
        bytes: &[u8],
        limits: WasmLimits,
        host: WasmHostPolicy,
    ) -> Result<WasmTool> {
        Self::from_bytes_with_policy_and_deadline(bytes, limits, host, MAX_COMPILE_WALL)
    }

    /// Compile a guest with an explicit host policy and an explicit wall
    /// deadline on the compile itself.
    ///
    /// Every ceiling is validated before anything is allocated or compiled, on
    /// the calling thread, so those refusals are deterministic: an empty or
    /// oversized module is `wasm/module`, text past [`MAX_WAT_BYTES`] is
    /// `wasm/module` before a byte of it is parsed, and a limit past its
    /// ceiling is `wasm/limits`. The compile itself — parsing the text, if
    /// any, and `Module::new` — then runs on a worker thread; the caller
    /// waits at most `max_compile_wall` for it. A compile that outlives the
    /// deadline is refused with `wasm/timeout` and the worker thread is
    /// detached: it finishes the compile on its own — its remaining work is
    /// bounded by the size ceilings — so a timed-out compile can never hold
    /// the caller past the deadline. A worker thread is never killed: there
    /// is no safe way to stop a wasmi compile from another thread, so the
    /// deadline is enforced by the join, not by the engine. A zero deadline
    /// is treated as one millisecond.
    ///
    /// The timeout is a `wasm/...` provider code, not the top-level
    /// `rpc/timeout` the call deadline reports (RPC-37): every construction
    /// refusal is a provider-coded `wasm/...` error, and the fuzz target
    /// (`fuzz/fuzz_targets/fuzz_wasm_module.rs`) asserts that shape, so a
    /// top-level code from construction would break it. The phase matters
    /// too: this deadline names the compile, the other names a call.
    pub fn from_bytes_with_policy_and_deadline(
        bytes: &[u8],
        limits: WasmLimits,
        mut host: WasmHostPolicy,
        max_compile_wall: Duration,
    ) -> Result<WasmTool> {
        if bytes.is_empty() || bytes.len() > MAX_MODULE_BYTES {
            return Err(provider("wasm/module"));
        }
        // Text expands far beyond its own size during compilation, and
        // compilation happens before any fuel exists: a 1 MiB text module
        // held the caller thread for ~1.1 s with no deadline anywhere
        // (RPC-39). The text ceiling is checked before a byte of it is
        // parsed, so no text input can buy more than ~70 ms of parse time.
        if !bytes.starts_with(b"\0asm") && bytes.len() > MAX_WAT_BYTES {
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
        // Compilation itself is the unbounded step: it runs before any fuel
        // exists, and neither the fuel meter nor the call deadline (RPC-37)
        // reaches it — both bound execution, and the module does not exist
        // yet. So the parse and the compile run on a worker thread under the
        // same wall discipline as execution (RPC-39): the caller waits at
        // most `max_compile_wall`, and a compile that outlives it is refused
        // with `wasm/timeout` while the worker is detached to finish the
        // compile on its own. A worker thread is never killed: there is no
        // safe way to stop a wasmi compile from another thread, so the
        // deadline is enforced by the join, not by the engine. A zero
        // deadline is treated as one millisecond.
        let max_compile_wall = max_compile_wall.max(Duration::from_millis(1));
        let worker_engine = engine.clone();
        let input = bytes.to_vec();
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::Builder::new()
            .name("active-wasm-compile".to_string())
            .spawn(move || {
                let outcome = (|| {
                    // Text is parsed to binary here, so the module ceiling bounds what the
                    // engine compiles rather than the source that produced it: a 1 MiB cap on
                    // the text bounded nothing (R-14 round 3, L-5).
                    let binary = if input.starts_with(b"\0asm") {
                        input
                    } else {
                        match wat::parse_bytes(&input) {
                            Ok(parsed) => parsed.into_owned(),
                            Err(_) => return Err(provider("wasm/module")),
                        }
                    };
                    if binary.len() > MAX_MODULE_BYTES {
                        return Err(provider("wasm/module"));
                    }
                    Module::new(&worker_engine, &binary).map_err(|_| provider("wasm/module"))
                })();
                let _ = tx.send(outcome);
            });
        let handle = match handle {
            Ok(handle) => handle,
            // The host could not start the compile's worker thread: the
            // guest never compiled, so there is nothing to report.
            Err(_) => return Err(provider("wasm/spawn")),
        };
        let module = match rx.recv_timeout(max_compile_wall) {
            Ok(module) => {
                // The worker sent its outcome, so it is already returning;
                // reaping it here keeps no finished thread behind.
                let _ = handle.join();
                module?
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // The deadline, not the meter, stopped this compile. The
                // worker is detached on purpose: it finishes the compile on
                // its own — its remaining work is bounded by the size
                // ceilings — so a timed-out compile can never hold the
                // caller past the deadline.
                drop(handle);
                return Err(provider("wasm/timeout"));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                // The worker died before it could report (a panic in the
                // parser or the compiler): the panic itself is on stderr
                // via the default hook, and the compile is the guest's
                // fault.
                let _ = handle.join();
                return Err(provider("wasm/module"));
            }
        };
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
            last_random_used: 0,
            random_cap: MAX_RANDOM_PER_CALL,
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

    /// Bytes of entropy the last call drew from the host.
    ///
    /// The cumulative per-call cap is the structural guard; the number is
    /// exposed so a test can assert it without a wall-clock race.
    pub fn entropy_used(&self) -> usize {
        self.last_random_used
    }

    /// Bytes the guest wrote to its log during the last call.
    pub fn log(&self) -> &[u8] {
        &self.log
    }

    /// Take the log produced during the most recent call.
    pub fn take_log(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.log)
    }

    /// Run the guest on `input` and return its output.
    ///
    /// The guest runs on a worker thread under a real wall-clock deadline
    /// derived from the fuel budget: `fuel / FUEL_PER_MS` milliseconds. Fuel
    /// alone never bound wall time (RPC-37): on a slow or loaded machine the
    /// same fuel takes far longer than the rate predicts, so the deadline is
    /// enforced by a clock around the execution, not by the meter. A call
    /// that outlives its deadline is refused with [`Error::Timeout`]
    /// (`rpc/timeout`); the fuel budget still bounds the guest's total work,
    /// and a guest that exhausts it first is refused with `wasm/fuel` as
    /// before. Use [`WasmTool::call_with_deadline`] to set the deadline
    /// explicitly instead of deriving it from fuel.
    pub fn call(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let max_wall = Duration::from_millis((self.limits.fuel / FUEL_PER_MS).max(1));
        self.call_with_deadline(input, max_wall)
    }

    /// Run the guest on `input` under an explicit wall-clock deadline.
    ///
    /// The guest runs on a worker thread; the calling thread waits at most
    /// `max_wall` for it. A guest that outlives the deadline is refused with
    /// [`Error::Timeout`] (`rpc/timeout`) and the worker thread is detached:
    /// it keeps running until its fuel exhausts (fuel still bounds the
    /// guest's total work), then exits. A worker thread is never killed:
    /// there is no safe way to stop a wasmi execution from another thread
    /// (wasmi 2.0.0 exposes no interrupt handle, and `Store::set_fuel`
    /// needs `&mut Store`, which the executing thread holds), so the
    /// deadline is enforced by the join, not by the engine. A zero deadline
    /// is treated as one millisecond. A timed-out call reports no guest log
    /// and no entropy draw: the worker owns that evidence and it is
    /// discarded with the result.
    ///
    /// The checks that need no execution run on the calling thread before
    /// the worker starts, so their refusals are deterministic: an input past
    /// the input window is `wasm/input`, and a grant too small to pay for
    /// the guest's own declared memory is `wasm/fuel`.
    pub fn call_with_deadline(&mut self, input: &[u8], max_wall: Duration) -> Result<Vec<u8>> {
        // Every refusal below must leave no log behind: `log()` is documented as
        // this call's evidence, and a stale buffer would attribute one caller's
        // bytes to another caller's failed call. The entropy metric is per call
        // for the same reason: a refusal before the guest starts must report
        // zero, not the previous call's draw (round 54, L-3).
        self.log.clear();
        self.last_random_used = 0;
        if input.len() > OUTPUT_OFFSET {
            return Err(provider("wasm/input"));
        }
        // The module's declared initial memory, read before anything is
        // allocated: this is the same reservation `WasmCall::run` recomputes
        // for the store setup. It is checked here, synchronously, so a grant
        // too small to pay for the guest's own memory is refused before any
        // thread starts instead of racing the deadline. The module's own
        // declaration, not the configured ceiling, is what instantiation
        // allocates (round 19, M1); a module with no exported memory falls
        // back to the ceiling because its size is not knowable here.
        let declared_kib = self
            .module
            .exports()
            .find(|export| export.name() == "memory")
            .and_then(|export| match export.ty() {
                wasmi::ExternType::Memory(memory) => Some(memory.minimum()),
                _ => None,
            })
            .map(|pages| pages.saturating_mul(64))
            .unwrap_or((self.limits.max_memory_bytes as u64).div_ceil(1024));
        let reserved_fuel = declared_kib.saturating_mul(FUEL_PER_MEMORY_KIB);
        if reserved_fuel > self.limits.fuel {
            // A grant too small to pay for the guest's own memory is a fuel
            // shortfall, not a resource over a ceiling (round 19, L2).
            return Err(provider("wasm/fuel"));
        }
        let max_wall = max_wall.max(Duration::from_millis(1));
        let engine = self.engine.clone();
        let module = self.module.clone();
        let limits = self.limits;
        let host = self.host;
        let random_cap = self.random_cap;
        let now_ms = self.now_ms;
        let input = input.to_vec();
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::Builder::new()
            .name("active-wasm-call".to_string())
            .spawn(move || {
                let mut call = WasmCall {
                    engine,
                    module,
                    limits,
                    host,
                    log: Vec::new(),
                    last_random_used: 0,
                    random_cap,
                    now_ms,
                };
                let result = call.run(&input);
                let outcome = CallOutcome {
                    result,
                    log: std::mem::take(&mut call.log),
                    random_used: call.last_random_used,
                };
                let _ = tx.send(outcome);
            });
        let handle = match handle {
            Ok(handle) => handle,
            // The host could not start the guest's worker thread: the guest
            // never ran, so there is no log and no draw to report.
            Err(_) => return Err(provider("wasm/spawn")),
        };
        match rx.recv_timeout(max_wall) {
            Ok(outcome) => {
                // The worker sent its outcome, so it is already returning;
                // reaping it here keeps no finished thread behind.
                let _ = handle.join();
                self.log = outcome.log;
                self.last_random_used = outcome.random_used;
                outcome.result
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // The deadline, not the meter, stopped this call. The worker
                // is detached on purpose: it runs until its fuel exhausts and
                // then exits, so a timed-out guest can never hold the caller
                // past the deadline, and its remaining work is still bounded
                // by the fuel grant it was given.
                drop(handle);
                Err(Error::Timeout)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                // The worker died before it could report (a panic in the
                // guest's execution): the panic itself is on stderr via the
                // default hook, and the call is the guest's fault.
                let _ = handle.join();
                Err(provider("wasm/trap"))
            }
        }
    }
}

/// What a guest worker reports back to the thread that called it.
///
/// The result plus the per-call evidence (`log`, `random_used`) that
/// [`WasmTool::log`] and [`WasmTool::entropy_used`] report. A timed-out call
/// never produces one: the worker owns the evidence and it is discarded.
struct CallOutcome {
    result: Result<Vec<u8>>,
    log: Vec<u8>,
    random_used: usize,
}

/// A guest call, owned by the worker thread that runs it.
///
/// This is the owned half of [`WasmTool`]: everything [`WasmCall::run`]
/// needs, so the worker never borrows the tool and the calling thread can
/// wait on the result with a deadline.
struct WasmCall {
    engine: Engine,
    module: Module,
    limits: WasmLimits,
    host: WasmHostPolicy,
    log: Vec<u8>,
    last_random_used: usize,
    random_cap: usize,
    now_ms: u64,
}

impl WasmCall {
    /// Instantiate the guest and run it, returning its output.
    ///
    /// This is the body [`WasmTool::call`] used to run inline: the checks
    /// that need no execution (input window, memory reservation) already ran
    /// on the calling thread in [`WasmTool::call_with_deadline`], so every
    /// refusal here comes from the guest or its fuel.
    fn run(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        // The module's declared initial memory, read before anything is
        // allocated: it is both the reservation below and the subtraction in the
        // growth ceiling. The module's own declaration, not the configured
        // ceiling, is what instantiation allocates (round 19, M1); a module with
        // no exported memory falls back to the ceiling because its size is not
        // knowable here.
        let declared_kib = self
            .module
            .exports()
            .find(|export| export.name() == "memory")
            .and_then(|export| match export.ty() {
                wasmi::ExternType::Memory(memory) => Some(memory.minimum()),
                _ => None,
            })
            .map(|pages| pages.saturating_mul(64))
            .unwrap_or((self.limits.max_memory_bytes as u64).div_ceil(1024));
        let reserved_fuel = declared_kib.saturating_mul(FUEL_PER_MEMORY_KIB);
        // wasmi debits `memory.grow` against the store's fuel (measured: 233
        // pages from a 30 000-fuel grant is refused out of fuel, while the same
        // guest under a 1e6-fuel grant runs), so the engine is the accounting.
        // The store limiter is the *bound*: it caps the total memory at the
        // declared memory plus what the unspent fuel could buy, so a guest
        // cannot reach a size the grant could never pay for even if the engine's
        // rate changed (round 20, HIGH #1; R-14 round 3, M-1).
        let spare_fuel = self.limits.fuel.saturating_sub(reserved_fuel);
        let declared_bytes = declared_kib.saturating_mul(1024);
        let growth = (spare_fuel / FUEL_PER_MEMORY_KIB).saturating_mul(1024);
        let affordable = declared_bytes
            .saturating_add(growth)
            .min(u64::try_from(self.limits.max_memory_bytes).unwrap_or(u64::MAX))
            .max(MIN_MEMORY_BYTES as u64) as usize;
        let limits = StoreLimitsBuilder::new()
            .memory_size(affordable)
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
            max_random: self.random_cap.min(MAX_RANDOM_PER_CALL),
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
            let now = i64::try_from(self.now_ms).unwrap_or(i64::MAX);
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
                        let next = used.saturating_add(len as usize);
                        if next > caller.data().max_random {
                            return -1;
                        }
                        let Some(memory) = caller
                            .get_export("memory")
                            .and_then(|export| export.into_memory())
                        else {
                            return -1;
                        };
                        // The pointer is checked before the allocation and the
                        // CSPRNG call: a guest that loops `random(OOB, 64 KiB)`
                        // otherwise makes the host allocate and fill 64 KiB per
                        // fuel while charging nothing (round 27, #2).
                        let start = ptr as usize;
                        let Some(end) = start.checked_add(len as usize) else {
                            return -1;
                        };
                        if end > memory.data(&caller).len() {
                            return -1;
                        }
                        let mut buffer = vec![0u8; len as usize];
                        if getrandom::fill(&mut buffer).is_err() {
                            return -1;
                        }
                        let data = memory.data_mut(&mut caller);
                        data[start..end].copy_from_slice(&buffer);
                        // Charged only after the copy: a refused pointer must
                        // not burn the call's entropy budget
                        // (round 23, #4).
                        caller.data_mut().random_used = next;
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
        // Reserve the module's declared initial memory before the instance
        // exists: a module that asks for 256 MiB must not spend the allocation
        // (and its wall time) before the refusal (round 18, #1). Charging the
        // ceiling instead refused a two-page module under a small grant
        // (round 19, M1); the declaration was read before the store existed.
        // The reservation was checked before the worker started (see
        // `call_with_deadline`): a grant too small to pay for the guest's own
        // memory is refused there, synchronously, so by the time the worker
        // runs this debit cannot fail for that reason.
        let granted = store.get_fuel().unwrap_or(0);
        if store.set_fuel(granted - reserved_fuel).is_err() {
            self.last_random_used = store.data().random_used;
            return Err(provider("wasm/fuel"));
        }
        let instance = match linker.instantiate_and_start(&mut store, &self.module) {
            Ok(instance) => instance,
            Err(error) => {
                self.log = std::mem::take(&mut store.data_mut().log);
                // A start function can draw entropy before it traps: the metric
                // is "bytes the last call drew", so it is recorded on every
                // return, not only on success (round 53, L-4).
                self.last_random_used = store.data().random_used;
                return Err(classify_instantiation(error));
            }
        };
        let memory = match instance.get_memory(&store, "memory") {
            Some(memory) => memory,
            None => {
                self.log = std::mem::take(&mut store.data_mut().log);
                self.last_random_used = store.data().random_used;
                return Err(provider("wasm/memory"));
            }
        };
        // The instance's declared memory was just materialised; charge it before
        // the guest can spend its whole grant on allocations it never pays for.
        let memory_kib = (memory.data_size(&store) as u64).div_ceil(1024);
        let memory_fuel = memory_kib.saturating_mul(FUEL_PER_MEMORY_KIB);
        let remaining = store.get_fuel().unwrap_or(0);
        if memory_fuel > reserved_fuel {
            // A start function that grew the memory spent fuel the reservation
            // did not cover: a shortfall, not a resource over a ceiling
            // (round 20, L9).
            self.log = std::mem::take(&mut store.data_mut().log);
            self.last_random_used = store.data().random_used;
            return Err(provider("wasm/fuel"));
        }
        if store
            .set_fuel(remaining + (reserved_fuel - memory_fuel))
            .is_err()
        {
            self.log = std::mem::take(&mut store.data_mut().log);
            self.last_random_used = store.data().random_used;
            return Err(provider("wasm/fuel"));
        }
        if memory.data(&store).len() < input.len() {
            // The start function already ran, so its log is this call's evidence
            // and its draw is this call's draw.
            self.log = std::mem::take(&mut store.data_mut().log);
            self.last_random_used = store.data().random_used;
            return Err(provider("wasm/memory"));
        }
        memory.data_mut(&mut store)[INPUT_OFFSET..INPUT_OFFSET + input.len()]
            .copy_from_slice(input);
        let run = match instance.get_typed_func::<i32, i32>(&store, "run") {
            Ok(run) => run,
            Err(_) => {
                self.log = std::mem::take(&mut store.data_mut().log);
                self.last_random_used = store.data().random_used;
                return Err(provider("wasm/entry"));
            }
        };
        let returned = match run.call(&mut store, input.len() as i32) {
            Ok(value) => value,
            Err(error) => {
                // Keep whatever the guest logged before it trapped: the log is
                // diagnostic evidence, not a success signal.
                self.log = std::mem::take(&mut store.data_mut().log);
                self.last_random_used = store.data().random_used;
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
        self.last_random_used = store.data().random_used;
        if returned < 0 {
            return Err(provider("wasm/output"));
        }
        let output_len = returned as usize;
        if output_len > self.limits.max_output_bytes {
            // A length past the output ceiling: distinct from the guest's own
            // `-1`, so a grant-bound refusal can be tokenized as a budget one
            // without relabelling a guest fault (round 31, F4).
            return Err(provider("wasm/output-limit"));
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
        // one. The kernel-facing path is the one an operator reads. The entropy
        // metric is per call for the same reason (round 55, L-2).
        self.log.clear();
        self.last_random_used = 0;
        // Budget refusals come before any policy or argument rule, as in the
        // other adapters: a zero wall or byte grant does no work, and a method
        // or a payload must not be an oracle past an exhausted grant
        // (round 26, #5; round 28, #4; round 36, #1).
        let granted = call.budget.max_wall_ms.saturating_mul(FUEL_PER_MS);
        let fuel = self.limits.fuel.min(granted);
        if fuel == 0 {
            return Err(Error::BudgetExceeded("wall"));
        }
        if call.budget.max_bytes == 0 {
            // An empty answer still costs a run; a zero-byte grant does no
            // work (round 22, F-B).
            return Err(Error::BudgetExceeded("byte"));
        }
        // The payload comes before the method, as in the MCP, HTTP and process
        // adapters: the same malformed call must not report one code here and
        // another there, because that difference fingerprints the adapter
        // (round 37, L1).
        if !call.payload.is_empty() {
            return Err(Error::InvalidArgument(
                "the wasm adapter reads its input from a single argument, not a payload",
            ));
        }
        // The same prefix every adapter uses: budget, payload, secret, scope,
        // method (round 38, #5).
        if crate::tool::args_contain_secret(&call.args) {
            // A secret anywhere in the argument is authority this adapter was
            // not granted; the text adapters report it the same way
            // (round 21, F5).
            return Err(Error::ToolPolicy("a secret is not a wasm argument"));
        }
        if call.path_scope.is_some() {
            // The input is bytes and the kernel inspects only `Value::Path`: a
            // scope attached here would read as confinement while enforcing
            // nothing (round 10, F-6).
            return Err(Error::ToolPolicy(
                "this adapter cannot enforce a path scope",
            ));
        }
        // The uniform prefix's argument-bytes step comes before the method and
        // before the shape loop: summing `Arg::wire_size` first means a call
        // whose arguments are too large reports the budget here, whatever its
        // method or shape, as the other three adapters do (round 41, F2).
        let grant = usize::try_from(call.budget.max_bytes).unwrap_or(usize::MAX);
        let mut arg_bytes = 0u64;
        for arg in &call.args {
            let Some(next) = arg_bytes.checked_add(Arg::wire_size(arg)) else {
                return Err(Error::BudgetExceeded("byte"));
            };
            arg_bytes = next;
        }
        if arg_bytes > call.budget.max_bytes {
            return Err(Error::BudgetExceeded("byte"));
        }
        if call.method != "run" {
            return Err(Error::MethodNotGranted {
                method: call.method.clone(),
            });
        }
        // Borrow the argument first: the byte grant bounds the input, and the
        // copy must happen only after every check (round 24, #5).
        let mut input: Option<&[u8]> = None;
        for arg in &call.args {
            let bytes: &[u8] = match arg {
                Arg::Value(Value::Text(text)) => text.as_bytes(),
                // A module image can carry a structural secret, which the
                // guest would read as plain input and could return mangled into
                // an opaque blob the egress check cannot see. The rule "a secret
                // is not a wasm argument" applies to this shape too
                // (R-14 round 3, L-3).
                Arg::Value(Value::Module(bytes)) => {
                    if crate::security::module_carries_a_secret(bytes) {
                        return Err(Error::ToolPolicy("a secret is not a wasm argument"));
                    }
                    bytes
                }
                // A secret is authority the capability did not grant to this
                // adapter, a policy refusal rather than a malformed argument
                // (round 20, L8).
                Arg::Value(Value::Secret) => {
                    return Err(Error::ToolPolicy("a secret is not a wasm argument"))
                }
                _ => {
                    return Err(Error::InvalidArgument(
                        "the wasm adapter takes exactly one text or module argument",
                    ))
                }
            };
            if input.is_some() {
                return Err(Error::InvalidArgument(
                    "the wasm adapter takes exactly one text or module argument",
                ));
            }
            if bytes.len() > grant {
                // Before the copy: the grant bounds the input too
                // (round 23, #3).
                return Err(Error::BudgetExceeded("byte"));
            }
            input = Some(bytes);
        }
        let Some(input) = input else {
            return Err(Error::InvalidArgument(
                "the wasm adapter takes exactly one text or module argument",
            ));
        };

        // The call's wall budget already bounds the guest: fuel was derived
        // above, before the argument rules (round 26, #5).
        if input.len() > OUTPUT_OFFSET {
            // The argument is written into the input area, which ends where the
            // output area begins. The copy must happen after this check, not
            // before it (round 42, L-1).
            return Err(provider("wasm/input"));
        }
        let input = input.to_vec();
        let mut limits = self.limits;
        limits.fuel = fuel;
        // The static output ceiling and the grant share are one ceiling, and
        // the tighter one tokenizes the refusal: a guest whose output passes
        // the static cap but not the share is a budget exhaustion
        // (round 27, #6).
        let share = grant.saturating_sub(input.len());
        let output_grant_bound = limits.max_output_bytes > share;
        limits.max_output_bytes = limits.max_output_bytes.min(share);
        // The guest log is provider-side state that the host buffers, so the
        // grant bounds it too: a one-byte grant used to buy a 64 KiB log
        // (round 28, #3).
        let mut host = self.host;
        host.max_log_bytes = host.max_log_bytes.min(share);
        let mut tool = WasmTool {
            engine: self.engine.clone(),
            module: self.module.clone(),
            limits,
            host,
            log: Vec::new(),
            last_random_used: 0,
            // Inheritance narrows: a child can never hold a wider entropy
            // ceiling than its parent (R-14 round 3, L-2).
            random_cap: self.random_cap.min(share),
            now_ms: call.now_ms,
        };
        // The wall budget binds twice: it derived the fuel above, and it is
        // the wall deadline the call runs under. Fuel alone never bound wall
        // time (RPC-37), so the grant is enforced by a clock here, not just
        // by the meter.
        let result =
            tool.call_with_deadline(&input, Duration::from_millis(call.budget.max_wall_ms));
        // Keep the guest's log even when the call was refused: a trap is exactly
        // when its diagnostics matter, and `call` cleared the buffer first so it
        // can only hold this call's bytes.
        self.log = std::mem::take(&mut tool.log);
        // Keep the entropy draw as an observable metric: the structural bound is
        // the per-call cap, and a wall-clock assertion on a loaded runner is not
        // a test of it (round 43, CI flake in wasm_round2_tests).
        self.last_random_used = tool.last_random_used;
        let output = match result {
            Ok(output) => output,
            Err(error)
                if output_grant_bound && error.provider_code() == Some("wasm/output-limit") =>
            {
                return Err(Error::BudgetExceeded("byte"))
            }
            Err(error) => return Err(error),
        };
        // Input, output, the guest log and the entropy draw share one grant:
        // three independent `share` caps let a 64 KiB grant buffer and generate
        // ~192 KiB in one call (round 23, #3; round 30, #1).
        let spent = output
            .len()
            .saturating_add(self.log.len())
            .saturating_add(tool.last_random_used);
        if spent > share {
            return Err(Error::BudgetExceeded("byte"));
        }
        // Guest output is bytes: a lossy UTF-8 conversion would hand the caller
        // text the guest never produced. Binary results travel as a module value.
        match String::from_utf8(output) {
            Ok(text) => Ok(Response::Value(Value::Text(text))),
            Err(error) => Ok(Response::Module(error.into_bytes())),
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
        // Everything else in this class is a structural instantiation failure
        // (a missing or mismatched import that reached the linker, an unexpected
        // start function). Reporting it as an import-policy refusal told an
        // operator to change a grant that was never the problem
        // (R-14 round 3, L-1).
        wasmi::errors::ErrorKind::Instantiation(_) => provider("wasm/instantiate"),
        _ => provider("wasm/instantiate"),
    }
}
