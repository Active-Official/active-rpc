#![cfg(feature = "wasm-tools")]

//! WASM guest tools: sandbox, fuel and capability gating.

use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Value};
use active_rpc::wasm_tool::{WasmLimits, WasmTool};
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
