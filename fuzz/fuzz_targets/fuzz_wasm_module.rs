#![no_main]

//! The WebAssembly sandbox: arbitrary module bytes must be refused or run under
//! the ceilings, never panic, never abort and never stall the host.
//!
//! Invariants under test:
//!
//! 1. `from_bytes_with_policy` is total over arbitrary bytes: it returns a tool
//!    or a `wasm/...` refusal, never a panic or an unbounded compile. A module
//!    over `MAX_MODULE_BYTES` is a limit refusal, and that is asserted on a
//!    buffer built in-target so `-max_len` cannot hide it.
//! 2. A tool the constructor accepted either runs under the limits and returns
//!    bounded output, or refuses with a `wasm/...` code. A limit that names a
//!    huge table, memory or log is refused before anything is allocated; the
//!    declared ceilings are asserted below, because a guest's own declaration is
//!    only reachable through a module whose shape `-max_len` cannot explore.
//! 3. The host log is per call and bounded: it never exceeds `max_log_bytes`,
//!    and a second call starts from an empty log.
//!
//! Run with `cargo +nightly fuzz run fuzz_wasm_module -- -runs=200000`.

use libfuzzer_sys::fuzz_target;

use active_rpc::wasm_tool::{
    WasmHostPolicy, WasmLimits, WasmTool, MAX_COMPILE_WALL, MAX_MODULE_BYTES,
};

/// Small ceilings keep one execution cheap: the point is the parser and the
/// sandbox, not a long-running guest.
const LIMITS: WasmLimits = WasmLimits {
    fuel: 50_000,
    max_memory_bytes: 2 * 65_536,
    max_output_bytes: 65_536,
    max_table_elements: 256,
};

fn policy() -> WasmHostPolicy {
    WasmHostPolicy {
        clock: true,
        random: false,
        log: true,
        max_log_bytes: 64,
        accept_wat: false,
    }
}

fuzz_target!(|data: &[u8]| {
    // Fixed positive control: a minimal module must be accepted, or the
    // construction branch below is dead (R-20 round 3, H1). It must also *run*:
    // a sandbox that refuses every call passed a construction-only control
    // (R-20 round 6, finding 8).
    {
        // The guest writes one byte at the output offset and returns its
        // length, so the control proves the ABI end to end.
        let wat = r#"(module (memory (export "memory") 2)
  (func (export "run") (param i32) (result i32)
    i32.const 65536 i32.const 65 i32.store8
    i32.const 1))"#;
        let mut tool = WasmTool::from_bytes_with_policy(
            wat.as_bytes(),
            LIMITS,
            WasmHostPolicy {
                accept_wat: true,
                ..policy()
            },
        )
        .expect("the fixed wat module compiles");
        // The control proves the sandbox runs a valid module end to end, so
        // it runs under an explicit generous wall, not `call()`'s
        // fuel-derived deadline: the 50 000-fuel grant derives 5 ms
        // (`fuel / FUEL_PER_MS / 2`, CI-FIX-RPC-12), which must cover thread
        // spawn plus wasmi instantiation, and a loaded CI runner missed it
        // once (run #378: `the fixed module runs: Timeout`, at this line).
        // The derived deadline is not what this control tests -- RPC-12's own
        // tests pin it, including the halving -- so the control takes
        // `MAX_COMPILE_WALL` (5 s) and can only fail on a real breakage
        // (CI-FIX-RPC-21).
        let output = tool
            .call_with_deadline(&[], MAX_COMPILE_WALL)
            .expect("the fixed module runs");
        assert_eq!(output, vec![65], "the guest's output did not come back");
    }

    // A limit that asks for more than the ceiling allows is refused, so a
    // caller cannot buy an unbounded table or memory by widening the policy.
    for limits in [
        WasmLimits {
            max_table_elements: usize::MAX,
            ..LIMITS
        },
        WasmLimits {
            max_memory_bytes: usize::MAX,
            ..LIMITS
        },
        WasmLimits {
            max_output_bytes: usize::MAX,
            ..LIMITS
        },
    ] {
        let error = WasmTool::from_bytes_with_policy(b"\0asm", limits, policy())
            .expect_err("a limit past the ceiling must be refused");
        assert_eq!(error.provider_code(), Some("wasm/limits"));
    }
    let error = WasmTool::from_bytes_with_policy(
        b"\0asm",
        LIMITS,
        WasmHostPolicy {
            max_log_bytes: usize::MAX,
            ..policy()
        },
    )
    .expect_err("a log ceiling past the maximum must be refused");
    assert_eq!(error.provider_code(), Some("wasm/limits"));

    // The declared ceiling itself: an oversize module is refused as a module
    // error, not handed to the compiler. Built here because libFuzzer cannot
    // reach it within `-max_len`, once per process so no input can skip it
    // (R-20 round 4, #8).
    static OVERSIZE: std::sync::Once = std::sync::Once::new();
    OVERSIZE.call_once(|| {
        let oversized = vec![0u8; MAX_MODULE_BYTES + 1];
        let error = WasmTool::from_bytes_with_policy(&oversized, LIMITS, policy())
            .expect_err("a module over the ceiling must be refused");
        assert_eq!(
            error.provider_code(),
            Some("wasm/module"),
            "an oversize module must be a module refusal: {error}"
        );
    });
    // A module over this size is refused by the ceiling before compiling, and a
    // bigger input would only slow the campaign down.
    // The module ceiling, not an arbitrary 64 KiB: a 1 MiB module is legal
    // input the parser must handle (R-20 round 3, L5).
    if data.is_empty() || data.len() > MAX_MODULE_BYTES {
        return;
    }
    match WasmTool::from_bytes_with_policy(data, LIMITS, policy()) {
        Ok(mut tool) => {
            let input = &data[..data.len().min(1024)];
            match tool.call(input) {
                Ok(output) => assert!(
                    output.len() <= LIMITS.max_output_bytes,
                    "the sandbox returned more output than its ceiling"
                ),
                Err(error) => assert!(
                    active_rpc::error::ERROR_CODES.contains(&error.code()),
                    "an unexpected error class: {error}"
                ),
            }
            // The host log is per call: a refusal leaves it empty, and a
            // successful call never exceeds the declared log ceiling.
            let log = tool.take_log();
            assert!(
                log.len() <= policy().max_log_bytes,
                "the host log kept {} bytes over its ceiling",
                log.len()
            );
            // The clock is seeded by the embedder, so a granted clock never
            // reaches the operating system.
            tool.set_time_ms(1);
            match tool.call(input) {
                Ok(output) => assert!(
                    output.len() <= LIMITS.max_output_bytes,
                    "the second call returned more output than its ceiling"
                ),
                Err(error) => assert!(
                    active_rpc::error::ERROR_CODES.contains(&error.code()),
                    "an unexpected error class on the second call: {error}"
                ),
            }
            tool.take_log();
        }
        Err(error) => {
            // Every construction refusal is a provider-coded `wasm/...` error.
            assert_eq!(error.code(), "rpc/provider", "unexpected: {error}");
            let text = error.to_string();
            assert!(
                text.contains("wasm/"),
                "a construction refusal must name its wasm code: {text}"
            );
        }
    }
});
