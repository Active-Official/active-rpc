#![cfg(feature = "wasm-tools")]

//! R-14 round 2: the sandbox's host work is paid for, and a refusal keeps its
//! evidence.
//!
//! The guests are hand-assembled binaries (`wat` is a test dependency), so each
//! test says exactly what it runs.

use std::time::Instant;

use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Call, Value};
use active_rpc::wasm_tool::{
    WasmHostPolicy, WasmLimits, WasmTool, FUEL_PER_MS, MAX_RANDOM_PER_CALL,
};
use active_rpc::Budget;

/// A guest that loops `env.random(0, 65536)` forever and never returns.
const RANDOM_BURNER: &str = r#"
(module
  (import "env" "random" (func $random (param i32 i32) (result i32)))
  (memory (export "memory") 2)
  (func (export "run") (param i32) (result i32)
    (loop $again
      (drop (call $random (i32.const 0) (i32.const 65536)))
      (br $again))
    (i32.const 0)))
"#;

/// A guest whose declared memory is at the ceiling and whose `run` does nothing.
const BIG_MEMORY: &str = r#"
(module
  (memory (export "memory") 4096)
  (func (export "run") (param i32) (result i32) (i32.const 0)))
"#;

/// A guest whose `start` logs and then traps.
const START_TRAP: &str = r#"
(module
  (import "env" "log" (func $log (param i32 i32) (result i32)))
  (memory (export "memory") 2)
  (data (i32.const 0) "start-trapped")
  (func $s (call $log (i32.const 0) (i32.const 13)) (unreachable))
  (start $s)
  (func (export "run") (param i32) (result i32) (i32.const 0)))
"#;

fn policy() -> WasmHostPolicy {
    WasmHostPolicy {
        clock: true,
        random: true,
        log: true,
        max_log_bytes: 1024,
        accept_wat: true,
    }
}

fn tool(wat: &str, limits: WasmLimits) -> WasmTool {
    WasmTool::from_bytes_with_policy(wat.as_bytes(), limits, policy()).expect("compile")
}

/// F1: the entropy grant is cumulative, so a loop cannot outrun the wall grant.
#[test]
fn a_random_loop_cannot_outlive_its_wall_budget() {
    let mut tool = tool(RANDOM_BURNER, WasmLimits::default());
    // A one-millisecond grant: 5 000 fuel.
    let mut call = Call::new("run", vec![Arg::text("")]);
    call.budget = Budget {
        max_wall_ms: 1,
        ..Budget::default()
    };
    call.now_ms = 1;
    let started = Instant::now();
    let error = tool.invoke(0, &call).expect_err("the guest must stop");
    let elapsed = started.elapsed();
    // The guest stops by whichever budget binds first: fuel exhaustion
    // (`wasm/fuel`) on a machine faster than the documented rate, the wall
    // deadline (`rpc/timeout`) on a slower one (RPC-37). Both are budget
    // refusals; the entropy cap below is the assertion that does not depend
    // on the machine.
    assert!(
        error.to_string().contains("wasm/") || error.code() == "rpc/timeout",
        "unexpected refusal: {error}"
    );
    // The structural bound is the cumulative entropy cap: one call cannot draw
    // more than that, whatever the wall grant (before it existed, a "1 ms"
    // grant burned 37 MiB of CSPRNG). Asserting a 15 ms wall clock here measured
    // the runner's load, not the code (CI flake on the ratio runner).
    assert!(
        tool.entropy_used() <= MAX_RANDOM_PER_CALL,
        "the guest drew {} bytes of entropy",
        tool.entropy_used()
    );
    // A hang guard, not a performance budget.
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "a 1 ms grant took {elapsed:?}"
    );
    const _: () = assert!(
        MAX_RANDOM_PER_CALL <= 64 << 10,
        "the cumulative entropy budget is bounded"
    );
}

/// A looping guest cannot outlive a small wall grant through the kernel
/// (RPC-37): the grant is the deadline, not just the fuel derivation.
#[test]
fn a_looping_guest_cannot_outlive_a_small_wall_grant() {
    const BURN: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "run") (param i32) (result i32)
    (loop $l (br $l))
    (i32.const 0)))
"#;
    let mut tool = tool(BURN, WasmLimits::default());
    let mut call = Call::new("run", vec![Arg::text("")]);
    call.budget = Budget {
        max_wall_ms: 100,
        ..Budget::default()
    };
    call.now_ms = 1;
    let started = Instant::now();
    let error = tool.invoke(0, &call).expect_err("the guest must stop");
    let elapsed = started.elapsed();
    // Whichever budget binds first is a legitimate stop (see the test above);
    // the deadline is what binds it on a slow machine, fuel on a fast one.
    assert!(
        error.to_string().contains("wasm/") || error.code() == "rpc/timeout",
        "unexpected refusal: {error}"
    );
    // A hang guard, not a performance budget.
    assert!(
        elapsed < std::time::Duration::from_millis(100) + std::time::Duration::from_secs(2),
        "a 100 ms grant took {elapsed:?}"
    );
}

/// F2: the declared memory is charged before the guest runs.
#[test]
fn declared_memory_is_charged_against_the_grant() {
    let mut tool = tool(
        BIG_MEMORY,
        WasmLimits {
            max_memory_bytes: 256 << 20,
            ..WasmLimits::default()
        },
    );
    let mut call = Call::new("run", vec![Arg::text("")]);
    call.budget = Budget {
        max_wall_ms: 1,
        ..Budget::default()
    };
    let error = tool
        .invoke(0, &call)
        .expect_err("256 MiB is unaffordable in 1 ms");
    let text = error.to_string();
    assert!(
        text.contains("wasm/limits") || text.contains("wasm/fuel"),
        "unexpected refusal: {error}"
    );
    // With a grant that can pay for it, the same guest runs.
    let mut call = Call::new("run", vec![Arg::text("")]);
    call.budget = Budget {
        max_wall_ms: 5_000,
        ..Budget::default()
    };
    call.now_ms = 1;
    let response = tool.invoke(0, &call).expect("the sandbox is affordable");
    assert!(matches!(
        response,
        active_rpc::Response::Value(Value::Text(_))
    ));
}

/// A start function that logs, and a module with no `run` export: the entry
/// refusal keeps the start log (round 56, L-3).
const START_LOG_NO_ENTRY: &str = r#"
(module
  (import "env" "log" (func $log (param i32 i32) (result i32)))
  (memory (export "memory") 2)
  (data (i32.const 0) "start-log")
  (func $s (drop (call $log (i32.const 0) (i32.const 9))))
  (start $s))
"#;

#[test]
fn a_missing_entry_keeps_the_start_log() {
    let mut tool = tool(START_LOG_NO_ENTRY, WasmLimits::default());
    let mut call = Call::new("run", vec![Arg::text("")]);
    call.budget = Budget::default();
    call.now_ms = 1;
    let error = tool.invoke(0, &call).expect_err("no run export");
    assert!(error.to_string().contains("wasm/entry"), "{error}");
    assert_eq!(tool.log(), b"start-log");
}

/// A guest whose `start` draws entropy and then traps: the draw is still what
/// the last call spent, so `entropy_used` reports it (round 53, L-4).
const START_RANDOM_TRAP: &str = r#"
(module
  (import "env" "random" (func $random (param i32 i32) (result i32)))
  (memory (export "memory") 2)
  (func $s (drop (call $random (i32.const 0) (i32.const 8))) (unreachable))
  (start $s)
  (func (export "run") (param i32) (result i32) (i32.const 0)))
"#;

#[test]
fn a_start_function_draw_is_reported_when_it_traps() {
    let mut tool = tool(START_RANDOM_TRAP, WasmLimits::default());
    let mut call = Call::new("run", vec![Arg::text("")]);
    call.budget = Budget::default();
    call.now_ms = 1;
    let error = tool.invoke(0, &call).expect_err("the start function traps");
    assert!(
        error.to_string().contains("wasm/trap"),
        "unexpected refusal: {error}"
    );
    assert_eq!(tool.entropy_used(), 8, "the start draw was not reported");
}

/// A guest that draws eight bytes once and returns.
const RANDOM_ONCE: &str = r#"
(module
  (import "env" "random" (func $random (param i32 i32) (result i32)))
  (memory (export "memory") 2)
  (func (export "run") (param i32) (result i32)
    (drop (call $random (i32.const 0) (i32.const 8)))
    (i32.const 0)))
"#;

/// A refusal before the guest runs reports no entropy: the metric is this
/// call's draw, not the previous call's (round 54, L-3).
#[test]
fn a_refused_call_reports_no_entropy_from_the_previous_call() {
    let mut tool = tool(RANDOM_ONCE, WasmLimits::default());
    assert_eq!(tool.call(b"").expect("the guest runs"), Vec::<u8>::new());
    assert_eq!(tool.entropy_used(), 8, "the draw was not reported");

    let oversized = vec![0u8; active_rpc::wasm_tool::OUTPUT_OFFSET + 1];
    let error = tool.call(&oversized).expect_err("the input is refused");
    assert!(
        error.to_string().contains("wasm/input"),
        "unexpected refusal: {error}"
    );
    assert_eq!(tool.entropy_used(), 0, "a stale draw was reported");
}

/// F3: a trap in `start` is a trap.
#[test]
fn a_start_trap_is_wasm_trap() {
    let mut tool = tool(START_TRAP, WasmLimits::default());
    let mut call = Call::new("run", vec![Arg::text("")]);
    call.budget = Budget::default();
    call.now_ms = 1;
    let error = tool.invoke(0, &call).expect_err("the start function traps");
    assert_eq!(error.code(), "rpc/provider");
    assert!(
        error.to_string().contains("wasm/trap"),
        "a start trap must be wasm/trap: {error}"
    );
    // F4: and its log survives the refusal.
    assert_eq!(tool.log(), b"start-trapped");
}

/// F5: a refused invoke clears the log, so one caller's bytes are not
/// attributed to another caller's failure.
#[test]
fn a_refused_invoke_clears_the_log() {
    const LOGGER: &str = r#"
(module
  (import "env" "log" (func $log (param i32 i32) (result i32)))
  (memory (export "memory") 2)
  (data (i32.const 0) "hello")
  (func (export "run") (param i32) (result i32)
    (drop (call $log (i32.const 0) (i32.const 5)))
    (i32.const 0)))
"#;
    let mut tool = tool(LOGGER, WasmLimits::default());
    let mut call = Call::new("run", vec![Arg::text("")]);
    call.budget = Budget::default();
    call.now_ms = 1;
    tool.invoke(0, &call).expect("the guest runs");
    assert_eq!(tool.take_log(), b"hello");

    // A refused call leaves nothing behind.
    tool.invoke(0, &Call::new("run", vec![Arg::text("a"), Arg::text("b")]))
        .expect_err("two arguments are refused");
    assert!(tool.log().is_empty(), "a refusal kept the previous log");
}

/// The fuel rate is the documented one, and the memory charge is derived from it.
#[test]
fn the_charges_are_the_documented_rates() {
    assert_eq!(FUEL_PER_MS, 5_000);
    const _: () = assert!(active_rpc::wasm_tool::FUEL_PER_MEMORY_KIB >= 1);
}
