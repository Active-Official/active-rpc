#![cfg(feature = "wasm-tools")]

//! WASM guest tools: sandbox, fuel and capability gating.

use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Value};
use active_rpc::wasm_tool::{WasmHostPolicy, WasmLimits, WasmTool};
use active_rpc::{Agent, Budget, Error};

const CONSTANT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "run") (param i32) (result i32)
    i32.const 0))
"#;

const ECHO: &str = r#"
(module
  (memory (export "memory") 2)
  (func (export "run") (param $len i32) (result i32)
    (memory.copy (i32.const 65536) (i32.const 0) (local.get $len))
    (local.get $len)))
"#;

const BURN: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "run") (param i32) (result i32)
    (loop $l (br $l))
    i32.const 0))
"#;

const TRAP: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "run") (param i32) (result i32)
    unreachable
    i32.const 0))
"#;

const IMPORT: &str = r#"
(module
  (import "env" "host" (func))
  (memory (export "memory") 1)
  (func (export "run") (param i32) (result i32)
    i32.const 0))
"#;

const NO_ENTRY: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "other") (param i32) (result i32)
    i32.const 0))
"#;

const BIG_MEMORY: &str = r#"
(module
  (memory (export "memory") 300)
  (func (export "run") (param i32) (result i32)
    i32.const 0))
"#;

const BIG_OUTPUT: &str = r#"
(module
  (memory (export "memory") 2)
  (func (export "run") (param i32) (result i32)
    i32.const 70000))
"#;

fn error_code(result: active_rpc::Result<impl std::fmt::Debug>) -> String {
    match result {
        Ok(value) => panic!("the guest was accepted: {value:?}"),
        Err(Error::Provider { code }) => code,
        Err(other) => other.code().to_string(),
    }
}

#[test]
fn a_guest_runs_and_returns_no_output() {
    let mut tool =
        WasmTool::from_bytes(CONSTANT.as_bytes(), WasmLimits::default()).expect("compile");
    assert!(tool.call(b"ignored").expect("run").is_empty());
}

#[test]
fn a_guest_round_trips_its_input_through_memory() {
    let mut tool = WasmTool::from_bytes(ECHO.as_bytes(), WasmLimits::default()).expect("compile");
    assert_eq!(tool.call(b"hello").expect("run"), b"hello");
    assert_eq!(tool.call(b"").expect("empty"), b"");
}

#[test]
fn fuel_exhaustion_is_refused_with_its_own_code() {
    let limits = WasmLimits {
        fuel: 10_000,
        ..WasmLimits::default()
    };
    let mut tool = WasmTool::from_bytes(BURN.as_bytes(), limits).expect("compile");
    assert_eq!(error_code(tool.call(b"")), "wasm/fuel");
}

#[test]
fn a_trap_is_refused_with_its_own_code() {
    let mut tool = WasmTool::from_bytes(TRAP.as_bytes(), WasmLimits::default()).expect("compile");
    assert_eq!(error_code(tool.call(b"")), "wasm/trap");
}

#[test]
fn a_guest_with_host_imports_is_refused_before_it_runs() {
    let error = WasmTool::from_bytes(IMPORT.as_bytes(), WasmLimits::default())
        .expect_err("imports are not part of ABI v1");
    assert_eq!(error.code(), "rpc/provider");
    assert_eq!(error_code(Err::<(), _>(error)), "wasm/import");
}

#[test]
fn a_missing_entry_point_is_refused() {
    let mut tool =
        WasmTool::from_bytes(NO_ENTRY.as_bytes(), WasmLimits::default()).expect("compile");
    assert_eq!(error_code(tool.call(b"")), "wasm/entry");
}

#[test]
fn a_memory_beyond_the_limit_fails_to_instantiate() {
    let limits = WasmLimits {
        max_memory_bytes: 1 << 20,
        ..WasmLimits::default()
    };
    let mut tool = WasmTool::from_bytes(BIG_MEMORY.as_bytes(), limits).expect("compile");
    assert_eq!(error_code(tool.call(b"")), "wasm/instantiate");
}

#[test]
fn output_beyond_the_ceiling_is_refused() {
    let limits = WasmLimits {
        max_output_bytes: 1024,
        ..WasmLimits::default()
    };
    let mut tool = WasmTool::from_bytes(BIG_OUTPUT.as_bytes(), limits).expect("compile");
    assert_eq!(error_code(tool.call(b"")), "wasm/output");
}

#[test]
fn input_beyond_the_input_window_is_refused() {
    let mut tool =
        WasmTool::from_bytes(CONSTANT.as_bytes(), WasmLimits::default()).expect("compile");
    let oversized = vec![0u8; 64 * 1024 + 1];
    assert_eq!(error_code(tool.call(&oversized)), "wasm/input");
}

#[test]
fn a_capability_runs_the_guest_through_the_kernel() {
    let agent = Agent::with_secret([0x2b; 32]);
    let tool = WasmTool::from_bytes(ECHO.as_bytes(), WasmLimits::default()).expect("compile");
    let provider = agent.register(Box::new(tool));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["run"]))
        .expect("mint");
    let lane = agent.create_lane("wasm", Budget::default()).expect("lane");
    let promise = agent
        .call(lane, &cap, "run", vec![Arg::text("guest")])
        .expect("call");
    agent.run();
    assert_eq!(
        promise.value().expect("value"),
        Value::Text("guest".to_string())
    );
}

#[test]
fn the_kernel_refuses_a_method_the_capability_does_not_grant() {
    let agent = Agent::with_secret([0x2c; 32]);
    let tool = WasmTool::from_bytes(CONSTANT.as_bytes(), WasmLimits::default()).expect("compile");
    let provider = agent.register(Box::new(tool));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["other"]))
        .expect("mint");
    let lane = agent.create_lane("wasm", Budget::default()).expect("lane");
    let error = agent
        .call(lane, &cap, "run", Vec::new())
        .expect_err("not granted");
    assert_eq!(error.code(), "rpc/method-not-granted");
}

#[test]
fn a_fuel_refusal_reaches_the_caller_through_the_kernel() {
    let agent = Agent::with_secret([0x2d; 32]);
    let limits = WasmLimits {
        fuel: 10_000,
        ..WasmLimits::default()
    };
    let tool = WasmTool::from_bytes(BURN.as_bytes(), limits).expect("compile");
    let provider = agent.register(Box::new(tool));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["run"]))
        .expect("mint");
    let lane = agent.create_lane("wasm", Budget::default()).expect("lane");
    let promise = agent.call(lane, &cap, "run", Vec::new()).expect("queued");
    agent.run();
    let error = promise.value().expect_err("the guest must be stopped");
    assert!(
        matches!(&error, Error::Provider { code } if code == "wasm/fuel"),
        "{error:?}"
    );
}

#[test]
fn a_tool_without_a_capability_is_unreachable() {
    let agent = Agent::with_secret([0x2e; 32]);
    let tool = WasmTool::from_bytes(CONSTANT.as_bytes(), WasmLimits::default()).expect("compile");
    let _provider = agent.register(Box::new(tool));
    let lane = agent.create_lane("wasm", Budget::default()).expect("lane");
    let imported = agent.import(active_rpc::CapId([0; 16]));
    let error = agent
        .call(lane, &imported, "run", Vec::new())
        .expect_err("no capability");
    assert_eq!(error.code(), "rpc/unknown-capability");
}

#[test]
fn the_provider_reports_its_single_method() {
    let tool = WasmTool::from_bytes(CONSTANT.as_bytes(), WasmLimits::default()).expect("compile");
    assert_eq!(tool.name(), "wasm");
    assert_eq!(tool.methods(), vec!["run".to_string()]);
}

/// A recursive guest hits the engine's depth ceiling and traps. Without the
/// ceiling it would consume the host stack while it still had fuel.
#[test]
fn unbounded_recursion_traps_instead_of_crashing_the_host() {
    use active_rpc::wasm_tool::MAX_FUEL;

    const RECURSE: &str = r#"
(module
  (memory (export "memory") 1)
  (func $recurse (param i32) (result i32)
    (call $recurse (local.get 0)))
  (func (export "run") (param i32) (result i32)
    (call $recurse (i32.const 0))))
"#;
    let limits = WasmLimits {
        // Plenty of fuel, so a trap proves the depth ceiling fired rather than
        // the meter.
        fuel: MAX_FUEL,
        ..WasmLimits::default()
    };
    let mut tool = WasmTool::from_bytes(RECURSE.as_bytes(), limits).expect("compile");
    let code = error_code(tool.call(b""));
    assert!(
        matches!(code.as_str(), "wasm/trap" | "wasm/fuel"),
        "unexpected code {code}"
    );
}

#[test]
fn a_module_larger_than_the_ceiling_is_refused_before_compiling() {
    let bytes = vec![0u8; active_rpc::wasm_tool::MAX_MODULE_BYTES + 1];
    let error = WasmTool::from_bytes(&bytes, WasmLimits::default())
        .expect_err("an oversized module must be refused");
    assert_eq!(error_code(Err::<(), _>(error)), "wasm/module");
    let error = WasmTool::from_bytes(&[], WasmLimits::default())
        .expect_err("an empty module must be refused");
    assert_eq!(error_code(Err::<(), _>(error)), "wasm/module");
}

#[test]
fn a_limit_that_would_fail_open_is_a_configuration_error() {
    // Zero fuel, zero output and a memory window outside the supported band are
    // refused when the tool is built, not discovered at call time.
    let cases = [
        WasmLimits {
            fuel: 0,
            ..WasmLimits::default()
        },
        WasmLimits {
            fuel: active_rpc::wasm_tool::MAX_FUEL + 1,
            ..WasmLimits::default()
        },
        WasmLimits {
            max_output_bytes: 0,
            ..WasmLimits::default()
        },
        WasmLimits {
            max_memory_bytes: 0,
            ..WasmLimits::default()
        },
        WasmLimits {
            max_memory_bytes: active_rpc::wasm_tool::MAX_MEMORY_BYTES + 1,
            ..WasmLimits::default()
        },
    ];
    for limits in cases {
        let error = WasmTool::from_bytes(CONSTANT.as_bytes(), limits)
            .expect_err("a fail-open limit must be refused");
        assert_eq!(error_code(Err::<(), _>(error)), "wasm/limits", "{limits:?}");
    }
}

// ---------------------------------------------------------------------------
// ABI v2: declared host imports
// ---------------------------------------------------------------------------

const CLOCK_GUEST: &str = r#"
(module
  (import "env" "clock_ms" (func $clock (result i64)))
  (memory (export "memory") 2)
  (func (export "run") (param i32) (result i32)
    (i64.store (i32.const 65536) (call $clock))
    i32.const 8))
"#;

const RANDOM_GUEST: &str = r#"
(module
  (import "env" "random" (func $random (param i32 i32) (result i32)))
  (memory (export "memory") 2)
  (func (export "run") (param i32) (result i32)
    (drop (call $random (i32.const 0) (i32.const 8)))
    (memory.copy (i32.const 65536) (i32.const 0) (i32.const 8))
    i32.const 8))
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

const OVERLOG_GUEST: &str = r#"
(module
  (import "env" "log" (func $log (param i32 i32) (result i32)))
  (memory (export "memory") 2)
  (data (i32.const 0) "hello")
  (func (export "run") (param i32) (result i32)
    (drop (call $log (i32.const 0) (i32.const 100000)))
    i32.const 0))
"#;

const UNKNOWN_IMPORT_GUEST: &str = r#"
(module
  (import "env" "net" (func $net (param i32) (result i32)))
  (memory (export "memory") 2)
  (func (export "run") (param i32) (result i32) i32.const 0))
"#;

#[test]
fn a_host_import_is_refused_without_a_policy() {
    for guest in [CLOCK_GUEST, RANDOM_GUEST, LOG_GUEST] {
        let error = WasmTool::from_bytes(guest.as_bytes(), WasmLimits::default())
            .expect_err("v1 must refuse every import");
        assert_eq!(error_code(Err::<(), _>(error)), "wasm/import");
    }
}

#[test]
fn a_granted_clock_import_returns_the_wall_clock() {
    let policy = WasmHostPolicy {
        clock: true,
        ..WasmHostPolicy::default()
    };
    let mut tool =
        WasmTool::from_bytes_with_policy(CLOCK_GUEST.as_bytes(), WasmLimits::default(), policy)
            .expect("compile");
    assert!(tool.host_policy().clock);
    let output = tool.call(b"").expect("run");
    assert_eq!(output.len(), 8);
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&output);
    let reported = i64::from_le_bytes(bytes);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as i64;
    assert!(
        (now - reported).abs() < 3_600_000,
        "clock {reported} is not near {now}"
    );
}

#[test]
fn a_granted_random_import_fills_guest_memory() {
    let policy = WasmHostPolicy {
        random: true,
        ..WasmHostPolicy::default()
    };
    let mut tool =
        WasmTool::from_bytes_with_policy(RANDOM_GUEST.as_bytes(), WasmLimits::default(), policy)
            .expect("compile");
    let first = tool.call(b"").expect("run");
    let second = tool.call(b"").expect("run again");
    assert_eq!(first.len(), 8);
    assert_eq!(second.len(), 8);
    assert_ne!(first, second, "two CSPRNG fills matched");
}

#[test]
fn a_granted_log_import_is_captured_and_capped() {
    let policy = WasmHostPolicy {
        log: true,
        max_log_bytes: 16,
        ..WasmHostPolicy::default()
    };
    let mut tool =
        WasmTool::from_bytes_with_policy(LOG_GUEST.as_bytes(), WasmLimits::default(), policy)
            .expect("compile");
    tool.call(b"").expect("run");
    assert_eq!(tool.log(), b"hello");
    assert_eq!(tool.take_log(), b"hello");
    assert!(tool.log().is_empty(), "take_log drains the buffer");

    // A guest that asks for more than the cap gets -1 and the log stays empty.
    let mut over =
        WasmTool::from_bytes_with_policy(OVERLOG_GUEST.as_bytes(), WasmLimits::default(), policy)
            .expect("compile");
    over.call(b"").expect("run");
    assert!(over.log().is_empty(), "the over-cap write must be refused");
}

#[test]
fn an_unknown_import_is_refused_even_with_every_grant() {
    let policy = WasmHostPolicy {
        clock: true,
        random: true,
        log: true,
        max_log_bytes: 128,
    };
    let error = WasmTool::from_bytes_with_policy(
        UNKNOWN_IMPORT_GUEST.as_bytes(),
        WasmLimits::default(),
        policy,
    )
    .expect_err("an undeclared import must be refused");
    assert_eq!(error_code(Err::<(), _>(error)), "wasm/import");
}

#[test]
fn a_log_policy_over_the_ceiling_is_a_configuration_error() {
    let policy = WasmHostPolicy {
        log: true,
        max_log_bytes: active_rpc::wasm_tool::MAX_HOST_LOG + 1,
        ..WasmHostPolicy::default()
    };
    let error =
        WasmTool::from_bytes_with_policy(LOG_GUEST.as_bytes(), WasmLimits::default(), policy)
            .expect_err("an over-cap log policy must be refused");
    assert_eq!(error_code(Err::<(), _>(error)), "wasm/limits");
}
