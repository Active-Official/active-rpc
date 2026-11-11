#![cfg(feature = "wasm-tools")]

//! Hardening of the WebAssembly sandbox (R-14 round 1): a hostile module must be
//! refused before it can allocate, a call's budget must bound the guest, the
//! clock must follow the kernel, an import must be the right kind of thing, and
//! a refusal must leave no stale evidence.

use active_rpc::budget::Budget;
use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Call, Value};
use active_rpc::wasm_tool::{
    WasmHostPolicy, WasmLimits, WasmTool, FUEL_PER_MS, MAX_TABLE_ELEMENTS,
};
use active_rpc::{Agent, Error};

fn binary(wat: &str) -> Vec<u8> {
    wat::parse_str(wat).expect("the fixture is valid WAT")
}

fn error_code(result: active_rpc::Result<impl std::fmt::Debug>) -> String {
    match result {
        Ok(value) => panic!("the call was accepted: {value:?}"),
        Err(Error::Provider { code }) => code,
        Err(other) => other.code().to_string(),
    }
}

const CONSTANT: &str = r#"
(module
  (memory (export "memory") 2)
  (func (export "run") (param i32) (result i32) i32.const 0))
"#;

const BURN: &str = r#"
(module
  (memory (export "memory") 2)
  (func (export "run") (param i32) (result i32)
    (local $n i64)
    loop
      local.get $n
      i64.const 1
      i64.add
      local.set $n
      br 0
    end
    i32.const 0))
"#;

const START_LOOP: &str = r#"
(module
  (memory (export "memory") 2)
  (func $start
    (local $n i64)
    loop
      local.get $n
      i64.const 1
      i64.add
      local.set $n
      br 0
    end)
  (start $start)
  (func (export "run") (param i32) (result i32) i32.const 0))
"#;

/// A module whose guest tries to grow its memory far past what the grant paid
/// for.
const GROW: &str = r#"
(module
  (memory (export "memory") 2 4096)
  (func (export "run") (param i32) (result i32)
    (if (result i32) (i32.eq (memory.grow (i32.const 4000)) (i32.const -1))
      (then (i32.const -1))
      (else (i32.const 0)))))
"#;

/// A module that declares a quarter-gigabyte of initial memory.
const BIG_MEMORY: &str = r#"
(module
  (memory (export "memory") 4096)
  (func (export "run") (param i32) (result i32) i32.const 0))
"#;

const BIG_TABLE: &str = r#"
(module
  (memory (export "memory") 2)
  (table 100000000 funcref)
  (func (export "run") (param i32) (result i32) i32.const 0))
"#;

/// An import named `env.log` that is a *memory*: the name is on the list, the
/// kind is not, so it must be refused at construction.
const WRONG_KIND: &str = r#"
(module
  (import "env" "log" (memory 1))
  (memory (export "memory") 2)
  (func (export "run") (param i32) (result i32) i32.const 0))
"#;

const LOG_GUEST: &str = r#"
(module
  (import "env" "log" (func $log (param i32 i32) (result i32)))
  (memory (export "memory") 2)
  (data (i32.const 0) "hello")
  (func (export "run") (param i32) (result i32)
    (drop (call $log (i32.const 0) (i32.const 5)))
    i32.const 0))
"#;

const BINARY_OUT: &str = r#"
(module
  (memory (export "memory") 2)
  (data (i32.const 65536) "\ff\fe")
  (func (export "run") (param i32) (result i32) i32.const 2))
"#;

// ---------------------------------------------------------------------------
// W1: a declared table is bounded
// ---------------------------------------------------------------------------

#[test]
fn a_module_with_a_huge_table_is_refused_without_allocating_it() {
    let started = std::time::Instant::now();
    let mut tool = WasmTool::from_bytes(&binary(BIG_TABLE), WasmLimits::default())
        .expect("the module compiles; the table is a resource question");
    let code = error_code(tool.call(b""));
    assert_eq!(code, "wasm/limits", "a huge table is a limit refusal");
    // Allocating the table would take seconds and gigabytes; a refusal is fast.
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "the table was allocated before it was refused: {:?}",
        started.elapsed()
    );
}

#[test]
fn the_table_ceiling_is_validated() {
    for elements in [0, MAX_TABLE_ELEMENTS + 1] {
        let limits = WasmLimits {
            max_table_elements: elements,
            ..WasmLimits::default()
        };
        let error = WasmTool::from_bytes(&binary(CONSTANT), limits)
            .expect_err("a table ceiling outside its band must be refused");
        assert_eq!(error_code(Err::<(), _>(error)), "wasm/limits");
    }
}

/// The declared memory ceiling is charged before the instance exists: a
/// quarter-gigabyte module under a small grant is refused quickly instead of
/// allocating first (round 18, #1).
#[test]
fn a_memory_reservation_is_charged_before_instantiation() {
    let started = std::time::Instant::now();
    let limits = WasmLimits {
        fuel: 10_000,
        max_memory_bytes: 256 << 20,
        ..WasmLimits::default()
    };
    let mut tool = WasmTool::from_bytes(&binary(BIG_MEMORY), limits).expect("compile");
    // The declared 256 MiB needs 524 288 fuel; the grant pays 10 000. A grant
    // too small for the guest's own memory is a fuel shortfall (round 19, L2).
    assert_eq!(error_code(tool.call(b"")), "wasm/fuel");
    assert!(
        started.elapsed() < std::time::Duration::from_millis(500),
        "the memory was materialised before the refusal: {:?}",
        started.elapsed()
    );

    // A small module is not charged for the configured ceiling: two pages under
    // a small grant still run (round 19, M1).
    let mut small = WasmTool::from_bytes(
        &binary(CONSTANT),
        WasmLimits {
            fuel: 10_000,
            max_memory_bytes: 256 << 20,
            ..WasmLimits::default()
        },
    )
    .expect("compile");
    assert!(small.call(b"").is_ok(), "a two-page module must run");
}

/// `memory.grow` is not charged by wasmi, so the store limiter must stop at
/// what the grant could pay for; a 256 MiB grow under a 10 000 fuel grant is
/// refused without allocating it (round 20, HIGH #1).
#[test]
fn a_memory_grow_is_capped_by_the_fuel_grant() {
    let started = std::time::Instant::now();
    let mut tool = WasmTool::from_bytes(
        &binary(GROW),
        WasmLimits {
            fuel: 10_000,
            max_memory_bytes: 256 << 20,
            ..WasmLimits::default()
        },
    )
    .expect("compile");
    // The guest returns -1 when the grow is refused, which the host reports as
    // a bad output length.
    assert_eq!(error_code(tool.call(b"")), "wasm/output");
    assert!(
        started.elapsed() < std::time::Duration::from_millis(500),
        "the grow was materialised: {:?}",
        started.elapsed()
    );
}

// ---------------------------------------------------------------------------
// W3: the call's wall budget bounds the guest
// ---------------------------------------------------------------------------

#[test]
fn a_wall_budget_bounds_the_fuel_a_guest_may_burn() {
    let agent = Agent::with_secret([0x44; 32]);
    let tool = WasmTool::from_bytes(&binary(BURN), WasmLimits::default()).expect("compile");
    let provider = agent.register(Box::new(tool)).expect("register provider");
    let lane = agent
        .create_lane("wasm-budget", Budget::default())
        .expect("lane");
    // The grant is the capability's. Ten milliseconds, not one: the sandbox's
    // own 16 MiB memory is charged against the same grant (2 fuel per KiB, so
    // 32 768 of the 50 000 fuel), and a grant that cannot pay for the sandbox is
    // a `wasm/limits` refusal before the guest runs at all (asserted below).
    let grant = Budget {
        max_wall_ms: 10,
        ..Budget::default()
    };
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["run"]).with_budget(grant))
        .expect("mint");
    let promise = agent
        .call(lane, &cap, "run", vec![Arg::text("")])
        .expect("queued");
    agent.run();
    let error = promise.value().expect_err("the guest must be stopped");
    assert!(
        matches!(&error, Error::Provider { code } if code == "wasm/fuel"),
        "a one-millisecond grant must stop a burner: {error:?}"
    );
    // The rate is the documented one: one millisecond buys FUEL_PER_MS fuel.
    assert_eq!(FUEL_PER_MS, 5_000);

    // A grant that cannot pay for the declared memory is refused before the
    // guest runs, rather than spending host CPU on an allocation it never
    // charged.
    let tiny = Budget {
        max_wall_ms: 1,
        ..Budget::default()
    };
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["run"]).with_budget(tiny))
        .expect("mint");
    let promise = agent
        .call(lane, &cap, "run", vec![Arg::text("")])
        .expect("queued");
    agent.run();
    let error = promise.value().expect_err("the sandbox is unaffordable");
    // `wasm/fuel` when the instantiation itself exhausts the grant (wasmi charges
    // for it), `wasm/limits` when the explicit memory charge does. Either way the
    // guest never runs, which is the property under test.
    assert!(
        matches!(&error, Error::Provider { code } if code == "wasm/limits" || code == "wasm/fuel"),
        "a grant below the sandbox's cost must be refused: {error:?}"
    );
}

// ---------------------------------------------------------------------------
// W4: a read-only capability cannot run guest code
// ---------------------------------------------------------------------------

#[test]
fn a_read_only_capability_refuses_the_guest() {
    let agent = Agent::with_secret([0x45; 32]);
    let tool = WasmTool::from_bytes(&binary(CONSTANT), WasmLimits::default()).expect("compile");
    let provider = agent.register(Box::new(tool)).expect("register provider");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["run"]).read_only())
        .expect("mint");
    let lane = agent
        .create_lane("wasm-ro", Budget::default())
        .expect("lane");
    let promise = agent
        .call(lane, &cap, "run", vec![Arg::text("")])
        .expect_err("read-only refuses a mutating method");
    // The refusal happens at the queue: running third-party guest code mutates
    // provider state (its log, its memory), which a read-only grant forbids.
    assert_eq!(promise.code(), "rpc/read-only");
}

// ---------------------------------------------------------------------------
// W6: an import must be a function of the granted signature
// ---------------------------------------------------------------------------

#[test]
fn an_import_with_the_right_name_but_the_wrong_kind_is_refused() {
    let policy = WasmHostPolicy {
        log: true,
        max_log_bytes: 64,
        ..WasmHostPolicy::default()
    };
    let error =
        WasmTool::from_bytes_with_policy(&binary(WRONG_KIND), WasmLimits::default(), policy)
            .expect_err("a memory named env.log is not a granted function");
    assert_eq!(error_code(Err::<(), _>(error)), "wasm/import");
}

// ---------------------------------------------------------------------------
// W7: a start function that runs out of fuel says so
// ---------------------------------------------------------------------------

#[test]
fn a_start_function_out_of_fuel_is_a_fuel_refusal() {
    // The default 16 MiB memory reservation would spend the whole grant before
    // the start function runs (round 18, #1), so the ceiling is the minimum:
    // the loop is then what exhausts the fuel.
    let limits = WasmLimits {
        fuel: 10_000,
        max_memory_bytes: active_rpc::wasm_tool::MIN_MEMORY_BYTES,
        ..WasmLimits::default()
    };
    let mut tool = WasmTool::from_bytes(&binary(START_LOOP), limits).expect("compile");
    assert_eq!(
        error_code(tool.call(b"")),
        "wasm/fuel",
        "the budget covers the start function, and the refusal says so"
    );
}

// ---------------------------------------------------------------------------
// W8: the argument contract
// ---------------------------------------------------------------------------

#[test]
fn a_call_must_carry_exactly_one_text_or_module_argument() {
    let agent = Agent::with_secret([0x46; 32]);
    let tool = WasmTool::from_bytes(&binary(CONSTANT), WasmLimits::default()).expect("compile");
    let provider = agent.register(Box::new(tool)).expect("register provider");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["run"]))
        .expect("mint");
    let lane = agent
        .create_lane("wasm-args", Budget::default())
        .expect("lane");

    for args in [
        Vec::new(),
        vec![Arg::value(Value::Int(7))],
        vec![Arg::text("a"), Arg::text("b")],
    ] {
        let promise = agent.call(lane, &cap, "run", args).expect("queued");
        agent.run();
        let error = promise
            .value()
            .expect_err("the argument contract refuses this");
        assert_eq!(error.code(), "rpc/invalid-argument");
    }

    // The one shape it accepts.
    let promise = agent
        .call(lane, &cap, "run", vec![Arg::text("payload")])
        .expect("queued");
    agent.run();
    promise.value().expect("one text argument");
}

// ---------------------------------------------------------------------------
// W10: a refused call leaves no stale log
// ---------------------------------------------------------------------------

#[test]
fn a_refused_call_leaves_no_log_from_an_earlier_one() {
    let policy = WasmHostPolicy {
        log: true,
        max_log_bytes: 64,
        ..WasmHostPolicy::default()
    };
    let mut tool =
        WasmTool::from_bytes_with_policy(&binary(LOG_GUEST), WasmLimits::default(), policy)
            .expect("compile");
    tool.call(b"").expect("run");
    assert_eq!(tool.log(), b"hello");

    let oversized = vec![0u8; 64 * 1024 + 1];
    assert_eq!(error_code(tool.call(&oversized)), "wasm/input");
    assert!(
        tool.log().is_empty(),
        "a refused call must not hand back an earlier call's log"
    );
}

// ---------------------------------------------------------------------------
// W11: binary output is bytes, not lossy text
// ---------------------------------------------------------------------------

#[test]
fn binary_output_travels_as_a_module_value() {
    let agent = Agent::with_secret([0x47; 32]);
    let tool = WasmTool::from_bytes(&binary(BINARY_OUT), WasmLimits::default()).expect("compile");
    let provider = agent.register(Box::new(tool)).expect("register provider");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["run"]))
        .expect("mint");
    let lane = agent
        .create_lane("wasm-out", Budget::default())
        .expect("lane");
    let promise = agent
        .call(lane, &cap, "run", vec![Arg::text("")])
        .expect("queued");
    agent.run();
    let reply = promise.value().expect("value");
    match &reply {
        Value::Module(bytes) => assert_eq!(bytes.as_slice(), [0xff, 0xfe]),
        other => panic!("binary output must not be lossy text: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// W14: text modules are refused by default
// ---------------------------------------------------------------------------

#[test]
fn a_text_module_is_refused_by_default() {
    let error = WasmTool::from_bytes(CONSTANT.as_bytes(), WasmLimits::default())
        .expect_err("text is not a binary module");
    assert_eq!(error_code(Err::<(), _>(error)), "wasm/module");

    // An embedder compiling its own fixtures can opt in; a peer never should.
    let policy = WasmHostPolicy {
        accept_wat: true,
        ..WasmHostPolicy::default()
    };
    WasmTool::from_bytes_with_policy(CONSTANT.as_bytes(), WasmLimits::default(), policy)
        .expect("an explicit opt-in accepts text");
}

/// A zero wall budget is refused before the argument rules, as in the other
/// adapters: a malformed argument must not mask the budget (round 26, #5).
#[test]
fn a_zero_wall_grant_precedes_the_argument_rules() {
    let mut tool = WasmTool::from_bytes(&binary(CONSTANT), WasmLimits::default()).expect("compile");
    let mut call = Call::new("run", vec![Arg::value(Value::Int(1))]);
    call.tool_allows_process = true;
    call.budget = Budget {
        max_wall_ms: 0,
        ..Budget::default()
    };
    let error =
        active_rpc::kernel::Provider::invoke(&mut tool, 0, &call).expect_err("a zero wall grant");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

/// A zero wall budget is refused before the scope or secret checks: the grant
/// is the first authority, as in the other adapters (round 28, #4).
#[test]
fn a_zero_wall_grant_precedes_the_wasm_policy_checks() {
    let mut tool = WasmTool::from_bytes(&binary(CONSTANT), WasmLimits::default()).expect("compile");
    let mut call = Call::new("run", vec![Arg::value(Value::Secret)]);
    call.tool_allows_process = true;
    call.path_scope = Some("app".to_string());
    call.budget = Budget {
        max_wall_ms: 0,
        ..Budget::default()
    };
    let error =
        active_rpc::kernel::Provider::invoke(&mut tool, 0, &call).expect_err("a zero wall grant");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

/// Output, the guest log and the entropy draw share one grant: three
/// independent caps let a 64 KiB grant buffer and generate ~192 KiB in one
/// call (round 30, #1).
#[test]
fn the_wasm_reply_and_log_share_one_grant() {
    const BOTH: &str = r#"
      (module
      (import "env" "log" (func $log (param i32 i32) (result i32)))
      (memory (export "memory") 2)
      (data (i32.const 0) "logbytes")
      (data (i32.const 65536) "outbytes")
      (func (export "run") (param i32) (result i32)
        (drop (call $log (i32.const 0) (i32.const 8)))
        i32.const 8))
      "#;
    let policy = WasmHostPolicy {
        log: true,
        max_log_bytes: 64,
        ..WasmHostPolicy::default()
    };
    let mut tool = WasmTool::from_bytes_with_policy(&binary(BOTH), WasmLimits::default(), policy)
        .expect("compile");
    let mut call = Call::new("run", vec![Arg::text("")]);
    call.tool_allows_process = true;
    // Eight bytes of output plus eight of log do not fit a ten-byte grant.
    call.budget = Budget {
        max_bytes: 10,
        ..Budget::default()
    };
    let error = active_rpc::kernel::Provider::invoke(&mut tool, 0, &call)
        .expect_err("output and log share the grant");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

/// A guest's own `-1` return is a guest fault, not grant exhaustion: only a
/// length past the ceiling is `wasm/output-limit`, and only that maps to a
/// budget refusal (round 31, F4).
#[test]
fn a_guest_negative_return_is_not_a_budget_refusal() {
    const REFUSE: &str = r#"
      (module
      (memory (export "memory") 2)
      (func (export "run") (param i32) (result i32) i32.const -1))
      "#;
    let mut tool = WasmTool::from_bytes(&binary(REFUSE), WasmLimits::default()).expect("compile");
    let mut call = Call::new("run", vec![Arg::text("")]);
    call.tool_allows_process = true;
    call.budget = Budget {
        max_bytes: 8,
        ..Budget::default()
    };
    let error =
        active_rpc::kernel::Provider::invoke(&mut tool, 0, &call).expect_err("the guest refused");
    assert_eq!(error.code(), "rpc/provider", "{error}");
    assert_eq!(error.provider_code(), Some("wasm/output"), "{error}");
}

/// A zero grant is refused before the method and the payload are inspected:
/// a spent capability must not answer either question (round 36, #1).
#[test]
fn a_zero_grant_precedes_the_method_and_payload_rules() {
    let tool = WasmTool::from_bytes(&binary(CONSTANT), WasmLimits::default()).expect("compile");
    let mut tool = tool;
    let mut call = Call::new("not-run", vec![Arg::Value(Value::Int(1))]);
    call.payload = vec![1, 2, 3];
    call.budget.max_wall_ms = 0;
    assert_eq!(
        error_code(Provider::invoke(&mut tool, 0, &call)),
        "rpc/budget-exceeded"
    );
    call.budget.max_wall_ms = 1_000;
    call.budget.max_bytes = 0;
    assert_eq!(
        error_code(Provider::invoke(&mut tool, 0, &call)),
        "rpc/budget-exceeded"
    );
}
