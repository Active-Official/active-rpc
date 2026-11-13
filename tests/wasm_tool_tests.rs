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

/// Compile a WAT fixture into the binary form a peer would send.
///
/// The sandbox refuses WebAssembly *text* by default (a 1 MiB text module can
/// expand into far more compiled code than 1 MiB), so every fixture goes through
/// the assembler first; `a_text_module_is_refused_by_default` pins that rule.
fn binary(wat: &str) -> Vec<u8> {
    wat::parse_str(wat).expect("the fixture is valid WAT")
}

/// A module of `n` empty functions plus the ABI `run` export, as WAT text.
///
/// Used to build large-but-legal modules for the compile-bound tests
/// (RPC-39): the text is ~16 bytes per function, the binary ~13.
fn many_functions_wat(n: usize) -> String {
    let mut wat = String::from("(module (memory (export \"memory\") 1)\n");
    for i in 0..n {
        wat.push_str(&format!("  (func $f{i})\n"));
    }
    wat.push_str("  (func (export \"run\") (param i32) (result i32) i32.const 0))\n");
    wat
}

/// A module whose `run` loops through a chain of `n` tiny functions, each
/// calling the next and the last returning its argument.
///
/// Used by the fuel-derived-deadline test (CI-FIX-RPC-22): a call chain burns
/// fuel far slower in wall time than the bare branch loop, because every call
/// pays the interpreter's frame setup for only a few fuel. Measured on the
/// fix machine, the 100-deep chain burns the default 1M fuel in ~522-560 ms
/// (1,785-1,915 fuel/ms, Windows native and Docker Linux alike), against
/// ~230-275 ms (3,636-4,347 fuel/ms) for the bare `(loop $l (br $l))` loop.
/// The derived deadline is 100 ms, so the chain's margin is ~5.2-5.6x: a
/// runner must burn more than five times faster than the fix machine to
/// exhaust the fuel inside the deadline. The bare loop's margin was only
/// ~2.3-2.8x, and a macOS CI runner in round 14 exceeded it and reported
/// `wasm/fuel` instead of the timeout. The chain is 100 deep, far below the
/// engine's 1,024-frame recursion ceiling.
fn call_chain_wat(n: usize) -> String {
    let mut wat = String::from("(module (memory (export \"memory\") 1)\n");
    for i in 0..n {
        if i + 1 < n {
            wat.push_str(&format!(
                "  (func $f{i} (param i32) (result i32) (call $f{} (local.get 0)))\n",
                i + 1
            ));
        } else {
            wat.push_str(&format!(
                "  (func $f{i} (param i32) (result i32) (local.get 0))\n",
            ));
        }
    }
    wat.push_str(
        "  (func (export \"run\") (param i32) (result i32)\n    (local $x i32)\n    (local.set $x (i32.const 1))\n    (loop $l\n      (local.set $x (call $f0 (local.get $x)))\n      (br $l))\n    i32.const 0))\n",
    );
    wat
}

fn error_code(result: active_rpc::Result<impl std::fmt::Debug>) -> String {
    match result {
        Ok(value) => panic!("the guest was accepted: {value:?}"),
        Err(Error::Provider { code }) => code,
        Err(other) => other.code().to_string(),
    }
}

#[test]
fn a_guest_runs_and_returns_no_output() {
    let mut tool = WasmTool::from_bytes(&binary(CONSTANT), WasmLimits::default()).expect("compile");
    assert!(tool.call(b"ignored").expect("run").is_empty());
}

#[test]
fn a_guest_round_trips_its_input_through_memory() {
    let mut tool = WasmTool::from_bytes(&binary(ECHO), WasmLimits::default()).expect("compile");
    assert_eq!(tool.call(b"hello").expect("run"), b"hello");
    assert_eq!(tool.call(b"").expect("empty"), b"");
}

#[test]
fn fuel_exhaustion_is_refused_with_its_own_code() {
    let limits = WasmLimits {
        fuel: 10_000,
        // The 16 MiB ceiling would spend the grant before the guest runs
        // (round 18, #1); this test is about the guest's own fuel.
        max_memory_bytes: active_rpc::wasm_tool::MIN_MEMORY_BYTES,
        ..WasmLimits::default()
    };
    let mut tool = WasmTool::from_bytes(&binary(BURN), limits).expect("compile");
    // The fuel code is pinned with the wall deadline held open: the same
    // guest under plain `call` stops by the 2 ms fuel-derived deadline on a
    // slow machine instead (RPC-37), so a bare `call` cannot pin `wasm/fuel`
    // for a loop. `call_with_deadline` with a generous deadline isolates the
    // fuel mechanism.
    assert_eq!(
        error_code(tool.call_with_deadline(b"", std::time::Duration::from_secs(10))),
        "wasm/fuel"
    );
}

/// A looping guest is stopped by an explicit wall deadline, not by its fuel
/// (RPC-37). The fuel budget is huge, so fuel exhaustion is seconds away in
/// any build; only the deadline can stop the guest in 100 ms.
#[test]
fn a_looping_guest_is_stopped_by_an_explicit_wall_deadline() {
    use active_rpc::wasm_tool::MAX_FUEL;

    let limits = WasmLimits {
        fuel: MAX_FUEL,
        ..WasmLimits::default()
    };
    let mut tool = WasmTool::from_bytes(&binary(BURN), limits).expect("compile");
    let started = std::time::Instant::now();
    let error = tool
        .call_with_deadline(b"", std::time::Duration::from_millis(100))
        .expect_err("the loop must stop");
    let elapsed = started.elapsed();
    assert!(matches!(error, Error::Timeout), "{error:?}");
    assert!(
        elapsed >= std::time::Duration::from_millis(100),
        "the call returned before its deadline: {elapsed:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_millis(100) + std::time::Duration::from_secs(2),
        "the deadline did not bind the call: {elapsed:?}"
    );
    // A timed-out call reports no partial evidence: the worker owns the log
    // and the draw, and both are discarded with its result.
    assert!(tool.log().is_empty(), "a timed-out call kept a log");
    assert_eq!(tool.entropy_used(), 0, "a timed-out call kept a draw");
}

/// The same deadline binds a direct `call`: the deadline is derived from the
/// fuel budget (`fuel / FUEL_PER_MS / 2`), so a default-limits loop stops at
/// ~100 ms with `rpc/timeout` instead of running until its fuel exhausts.
/// The halving is load-bearing: at the unhalved rate the deadline was 200 ms
/// against a 232-268 ms burn on the fix machine, and a faster CI runner
/// burned the fuel inside the deadline and reported `wasm/fuel` instead
/// (CI-FIX-RPC-12).
/// The guest is a 100-deep call chain, not the bare branch loop, because the
/// deadline only binds while the guest burns its fuel slower than the rate the
/// derivation assumes (10 000 fuel/ms): the bare loop burns ~3 600-4 350
/// fuel/ms on the fix machine, a ~2.3-2.8x margin, and a macOS CI runner in
/// round 14 exceeded it and reported `wasm/fuel` at the `Timeout` assertion
/// below (CI-FIX-RPC-22). The chain burns ~1 785-1 915 fuel/ms, so its
/// ~522-560 ms burn leaves a ~5.2-5.6x margin on the same 100 ms deadline.
/// The production derivation is unchanged; only the test's guest is slower
/// to burn, which is what makes the timeout outcome deterministic. The bare
/// loop keeps its own pin in `fuel_exhaustion_is_refused_with_its_own_code`,
/// where the wall is held open and no race exists.
#[test]
fn a_looping_guest_is_stopped_by_the_fuel_derived_wall_deadline() {
    let mut tool = WasmTool::from_bytes(&binary(&call_chain_wat(100)), WasmLimits::default())
        .expect("compile");
    let started = std::time::Instant::now();
    let error = tool.call(b"").expect_err("the loop must stop");
    let elapsed = started.elapsed();
    assert!(matches!(error, Error::Timeout), "{error:?}");
    assert!(
        elapsed >= std::time::Duration::from_millis(100),
        "the call returned before its deadline: {elapsed:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_millis(100) + std::time::Duration::from_secs(2),
        "the deadline did not bind the call: {elapsed:?}"
    );
}

#[test]
fn a_trap_is_refused_with_its_own_code() {
    let mut tool = WasmTool::from_bytes(&binary(TRAP), WasmLimits::default()).expect("compile");
    assert_eq!(error_code(tool.call(b"")), "wasm/trap");
}

#[test]
fn a_guest_with_host_imports_is_refused_before_it_runs() {
    let error = WasmTool::from_bytes(&binary(IMPORT), WasmLimits::default())
        .expect_err("imports are not part of ABI v1");
    assert_eq!(error.code(), "rpc/provider");
    assert_eq!(error_code(Err::<(), _>(error)), "wasm/import");
}

#[test]
fn a_missing_entry_point_is_refused() {
    let mut tool = WasmTool::from_bytes(&binary(NO_ENTRY), WasmLimits::default()).expect("compile");
    assert_eq!(error_code(tool.call(b"")), "wasm/entry");
}

#[test]
fn a_memory_beyond_the_limit_fails_to_instantiate() {
    let limits = WasmLimits {
        max_memory_bytes: 1 << 20,
        ..WasmLimits::default()
    };
    let mut tool = WasmTool::from_bytes(&binary(BIG_MEMORY), limits).expect("compile");
    // A declared memory beyond the ceiling is a resource refusal, not a
    // malformed module: the guest never runs and the host never allocates it.
    assert_eq!(error_code(tool.call(b"")), "wasm/limits");
}

#[test]
fn output_beyond_the_ceiling_is_refused() {
    let limits = WasmLimits {
        max_output_bytes: 1024,
        ..WasmLimits::default()
    };
    let mut tool = WasmTool::from_bytes(&binary(BIG_OUTPUT), limits).expect("compile");
    // A length past the output ceiling has its own code: the guest's own `-1`
    // stays `wasm/output`, and only the ceiling maps to a budget refusal when
    // the grant is the tighter bound (round 31, F4).
    assert_eq!(error_code(tool.call(b"")), "wasm/output-limit");
}

#[test]
fn input_beyond_the_input_window_is_refused() {
    let mut tool = WasmTool::from_bytes(&binary(CONSTANT), WasmLimits::default()).expect("compile");
    let oversized = vec![0u8; 64 * 1024 + 1];
    assert_eq!(error_code(tool.call(&oversized)), "wasm/input");
}

#[test]
fn a_capability_runs_the_guest_through_the_kernel() {
    let agent = Agent::with_secret([0x2b; 32]);
    let tool = WasmTool::from_bytes(&binary(ECHO), WasmLimits::default()).expect("compile");
    let provider = agent.register(Box::new(tool)).expect("register provider");
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
    let tool = WasmTool::from_bytes(&binary(CONSTANT), WasmLimits::default()).expect("compile");
    let provider = agent.register(Box::new(tool)).expect("register provider");
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
        // The 16 MiB ceiling would spend the grant before the guest runs
        // (round 18, #1); this test is about the guest's own fuel.
        max_memory_bytes: active_rpc::wasm_tool::MIN_MEMORY_BYTES,
        ..WasmLimits::default()
    };
    let tool = WasmTool::from_bytes(&binary(BURN), limits).expect("compile");
    let provider = agent.register(Box::new(tool)).expect("register provider");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["run"]))
        .expect("mint");
    let lane = agent.create_lane("wasm", Budget::default()).expect("lane");
    let promise = agent
        .call(lane, &cap, "run", vec![Arg::text("")])
        .expect("queued");
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
    let tool = WasmTool::from_bytes(&binary(CONSTANT), WasmLimits::default()).expect("compile");
    let _provider = agent.register(Box::new(tool)).expect("register provider");
    let lane = agent.create_lane("wasm", Budget::default()).expect("lane");
    let imported = agent.import(active_rpc::CapId([0; 16]));
    let error = agent
        .call(lane, &imported, "run", Vec::new())
        .expect_err("no capability");
    assert_eq!(error.code(), "rpc/unknown-capability");
}

#[test]
fn the_provider_reports_its_single_method() {
    let tool = WasmTool::from_bytes(&binary(CONSTANT), WasmLimits::default()).expect("compile");
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
    let mut tool = WasmTool::from_bytes(&binary(RECURSE), limits).expect("compile");
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

/// A WAT module past the text ceiling is refused before parsing (RPC-39).
///
/// Text expands far beyond its own size during compilation, and compilation
/// happens before any fuel exists: a 1 MiB text module held the caller
/// thread for ~1.1 s with no deadline anywhere. The 64 KiB text ceiling is
/// checked before a byte of it is parsed, so the refusal is immediate.
#[test]
fn a_wat_module_over_the_text_ceiling_is_refused_before_parsing() {
    let wat = many_functions_wat(5_000);
    assert!(
        wat.len() > active_rpc::wasm_tool::MAX_WAT_BYTES,
        "the fixture must be past the text ceiling: {} bytes",
        wat.len()
    );
    let policy = WasmHostPolicy {
        accept_wat: true,
        ..WasmHostPolicy::default()
    };
    let start = std::time::Instant::now();
    let error = WasmTool::from_bytes_with_policy(wat.as_bytes(), WasmLimits::default(), policy)
        .expect_err("text past the ceiling must be refused");
    assert_eq!(error_code(Err::<(), _>(error)), "wasm/module");
    assert!(
        start.elapsed().as_millis() < 1_000,
        "the refusal must come from the ceiling, not from a parse that ran: {:?}",
        start.elapsed()
    );
}

/// A WAT module under the text ceiling still compiles (RPC-39).
///
/// The ceiling must bind hostile text without refusing a hand-written tool:
/// 4,000 empty functions is ~63 KiB of text, far above any hand-written
/// tool and just under the ceiling.
#[test]
fn a_wat_module_under_the_text_ceiling_still_compiles() {
    let wat = many_functions_wat(4_000);
    assert!(
        wat.len() <= active_rpc::wasm_tool::MAX_WAT_BYTES,
        "the fixture must be under the text ceiling: {} bytes",
        wat.len()
    );
    let policy = WasmHostPolicy {
        accept_wat: true,
        ..WasmHostPolicy::default()
    };
    let mut tool = WasmTool::from_bytes_with_policy(wat.as_bytes(), WasmLimits::default(), policy)
        .expect("text under the ceiling must compile");
    assert!(tool.call(b"").expect("run").is_empty());
}

/// A compile that outlives its deadline is refused with `wasm/timeout`
/// (RPC-39).
///
/// The module below compiles in ~230-310 ms in debug on the fix machine
/// (60,000 empty functions), so a 1 ms deadline can only be met by the
/// deadline mechanism, not by a fast compile; a zero deadline is clamped
/// to 1 ms rather than read as "no deadline".
/// The 20,000-function module this test used first compiles in ~80 ms in
/// debug, a ~80x margin on the 1 ms deadline — and an Official macOS CI
/// runner in round 15 still finished inside it (CI-FIX-RPC-23): the 1 ms
/// window is measured from the `recv_timeout` call, so a main thread
/// descheduled between the worker spawn and the wait hands the worker the
/// whole scheduling delay as well as the 1 ms, and a fast, loaded runner
/// can spend it. The 60,000-function module needs more than three times
/// that delay to flip (worst measured rep 203 ms, worst median 232 ms
/// across Windows native and Docker Linux; round-17 probe: native
/// 211-260 ms, Docker 212-348 ms, 20 reps each).
/// The precondition floor below is 50 ms, not the 100 ms round 16 set:
/// a Ratio Linux CI runner compiled the fixture in 99.377 ms in round 16
/// (run #381) and tripped the 100 ms guard — the guard was set ~2x below
/// the worst LOCAL rep (203 ms), but CI Linux is ~2x faster than the fix
/// machine, so local worst reps do not bound CI. 50 ms sits ~2x below the
/// fastest CI compile observed (99.377 ms) and 50x above the 1 ms deadline
/// it must outlive. A larger fixture does not buy more: 70,000 functions
/// is 91% of the 1 MiB ceiling and would compile in only ~116 ms on that
/// runner. Its binary stays under the 1 MiB module ceiling (asserted
/// below); the neighbouring large-binary test keeps its own 20,000-function
/// pin that a legal module compiles inside the 5 s default.
#[test]
fn a_compile_that_outlives_its_deadline_is_refused_with_timeout() {
    let binary = binary(&many_functions_wat(60_000));
    assert!(
        binary.len() <= active_rpc::wasm_tool::MAX_MODULE_BYTES,
        "the fixture must stay under the module ceiling: {} bytes",
        binary.len()
    );
    // Precondition, measured not assumed: the fixture must outlive the
    // 1 ms deadline by a wide margin on this hardware, or the refusal
    // below pins nothing. The floor is 50 ms: ~2x below the fastest
    // compile observed anywhere (99.377 ms, Ratio Linux CI, round 16)
    // and 50x above the deadline. If hardware ever compiles it in under
    // 50 ms, this fails here with a clear message instead of flaking at
    // the `expect_err` below — the signal to enlarge the fixture again.
    let precondition = std::time::Instant::now();
    let _ = WasmTool::from_bytes(&binary, WasmLimits::default()).expect("the fixture must compile");
    assert!(
        precondition.elapsed() >= std::time::Duration::from_millis(50),
        "the fixture compiled too fast to pin the deadline: {:?}",
        precondition.elapsed()
    );
    for deadline in [
        std::time::Duration::from_millis(1),
        std::time::Duration::ZERO,
    ] {
        let start = std::time::Instant::now();
        let error = WasmTool::from_bytes_with_policy_and_deadline(
            &binary,
            WasmLimits::default(),
            WasmHostPolicy::default(),
            deadline,
        )
        .expect_err("a compile past its deadline must be refused");
        assert_eq!(error_code(Err::<(), _>(error)), "wasm/timeout");
        assert!(
            start.elapsed().as_millis() < 2_000,
            "the deadline must bind the caller: {:?}",
            start.elapsed()
        );
    }
}

/// A large binary module still compiles under the default deadline (RPC-39).
///
/// The deadline must bind hostile compiles without refusing legitimate
/// work: a 252 KiB binary (20,000 functions) compiles in ~80 ms in debug,
/// far inside the 5 s default.
#[test]
fn a_large_binary_module_compiles_within_the_default_deadline() {
    let binary = binary(&many_functions_wat(20_000));
    let mut tool = WasmTool::from_bytes(&binary, WasmLimits::default())
        .expect("a large legal module must compile within the default deadline");
    assert!(tool.call(b"").expect("run").is_empty());
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
        let error = WasmTool::from_bytes(&binary(CONSTANT), limits)
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
        let error = WasmTool::from_bytes(&binary(guest), WasmLimits::default())
            .expect_err("v1 must refuse every import");
        assert_eq!(error_code(Err::<(), _>(error)), "wasm/import");
    }
}

#[test]
fn a_granted_clock_import_reports_the_embedder_clock() {
    let policy = WasmHostPolicy {
        clock: true,
        ..WasmHostPolicy::default()
    };
    let mut tool =
        WasmTool::from_bytes_with_policy(&binary(CLOCK_GUEST), WasmLimits::default(), policy)
            .expect("compile");
    assert!(tool.host_policy().clock);
    // A guest must not read the operating system's clock behind the kernel's
    // back: it sees the time the embedder seeded, so a virtual-clock kernel
    // stays deterministic (and a wall-clock one passes `Call::now_ms`).
    assert_eq!(tool.time_ms(), 0);
    let output = tool.call(b"").expect("run");
    assert_eq!(output.len(), 8);
    assert_eq!(
        i64::from_le_bytes(output[..8].try_into().expect("8 bytes")),
        0
    );

    tool.set_time_ms(1_793_571_941_004);
    let output = tool.call(b"").expect("run");
    assert_eq!(
        i64::from_le_bytes(output[..8].try_into().expect("8 bytes")),
        1_793_571_941_004,
        "the guest reads the seeded time"
    );
}

/// Through the kernel the guest sees the kernel's clock, not the host's.
#[test]
fn a_guest_reads_the_kernel_clock_through_the_kernel() {
    let agent = Agent::with_secret([0x3a; 32]);
    agent.enable_receipts(true);
    let policy = WasmHostPolicy {
        clock: true,
        ..WasmHostPolicy::default()
    };
    let tool =
        WasmTool::from_bytes_with_policy(&binary(CLOCK_GUEST), WasmLimits::default(), policy)
            .expect("compile");
    let provider = agent.register(Box::new(tool)).expect("register provider");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["run"]))
        .expect("mint");
    let lane = agent
        .create_lane("wasm-clock", Budget::default())
        .expect("lane");
    let promise = agent
        .call(lane, &cap, "run", vec![Arg::text("")])
        .expect("call");
    agent.run();
    let value = promise.value().expect("value");
    let text = match value {
        Value::Text(text) => text,
        other => panic!("expected text, got {other:?}"),
    };
    let reported = i64::from_le_bytes(
        text.as_bytes()
            .try_into()
            .expect("the guest returned eight bytes"),
    );
    let kernel_time = agent.now_ms() as i64;
    assert!(
        reported <= kernel_time && reported > 0,
        "the guest read {reported}, the kernel clock was {kernel_time}"
    );
}

#[test]
fn a_granted_random_import_fills_guest_memory() {
    let policy = WasmHostPolicy {
        random: true,
        ..WasmHostPolicy::default()
    };
    let mut tool =
        WasmTool::from_bytes_with_policy(&binary(RANDOM_GUEST), WasmLimits::default(), policy)
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
        WasmTool::from_bytes_with_policy(&binary(LOG_GUEST), WasmLimits::default(), policy)
            .expect("compile");
    tool.call(b"").expect("run");
    assert_eq!(tool.log(), b"hello");
    assert_eq!(tool.take_log(), b"hello");
    assert!(tool.log().is_empty(), "take_log drains the buffer");

    // A guest that asks for more than the cap gets -1 and the log stays empty.
    let mut over =
        WasmTool::from_bytes_with_policy(&binary(OVERLOG_GUEST), WasmLimits::default(), policy)
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
        accept_wat: true,
    };
    let error = WasmTool::from_bytes_with_policy(
        &binary(UNKNOWN_IMPORT_GUEST),
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
    let error = WasmTool::from_bytes_with_policy(&binary(LOG_GUEST), WasmLimits::default(), policy)
        .expect_err("an over-cap log policy must be refused");
    assert_eq!(error_code(Err::<(), _>(error)), "wasm/limits");
}

#[test]
fn a_log_grant_without_a_cap_is_a_configuration_error() {
    // RPC-48(a): `log: true` with the default cap 0 used to compile and then
    // capture nothing — a granted import that can never log (W2's probe
    // `w2_rpc48_wasm_log_true_without_cap_captures_nothing`:
    // `captured-log=[]`). A log grant without a cap is a configuration error,
    // exactly like a cap over the ceiling
    // (`a_log_policy_over_the_ceiling_is_a_configuration_error`): the
    // embedder asked for logging and gave it no room, so construction
    // refuses with `wasm/limits` instead of building a useless tool.
    let policy = WasmHostPolicy {
        log: true,
        ..WasmHostPolicy::default()
    };
    let error = WasmTool::from_bytes_with_policy(&binary(LOG_GUEST), WasmLimits::default(), policy)
        .expect_err("a log grant without a cap must be refused");
    assert_eq!(error_code(Err::<(), _>(error)), "wasm/limits");
}

#[test]
fn a_log_grant_with_a_cap_still_captures() {
    // RPC-48(a) control: the refusal above is about a *missing* cap, not
    // about logging itself — W2's control shape (`max_log_bytes=1024`
    // captures `hello-log`); LOG_GUEST logs `hello`, which fits in 1024.
    let policy = WasmHostPolicy {
        log: true,
        max_log_bytes: 1024,
        ..WasmHostPolicy::default()
    };
    let mut tool =
        WasmTool::from_bytes_with_policy(&binary(LOG_GUEST), WasmLimits::default(), policy)
            .expect("compile");
    tool.call(b"").expect("run");
    assert_eq!(tool.log(), b"hello");
}

#[test]
fn an_input_at_the_window_ceiling_still_runs() {
    // RPC-48(a): `run` receives `input.len()` as an i32. The call window
    // already refuses any input past 64 KiB with `wasm/input`, so the live
    // maximum that can reach the cast is exactly 64 KiB; this pins that
    // boundary end to end (ECHO copies the input to the output window and
    // returns its length).
    let mut tool = WasmTool::from_bytes(&binary(ECHO), WasmLimits::default()).expect("compile");
    let input = vec![b'x'; 64 * 1024];
    // This pins the 64 KiB input-window boundary, not the derived wall:
    // a bare `call` derives its wall from the default 1M fuel as 100 ms
    // (`fuel / FUEL_PER_MS / 2`), and on a loaded machine the worker thread can
    // starve past it even though the copy itself is milliseconds (round-4
    // probe: loaded call latency median ~35 ms, max ~75 ms running alone,
    // and `run: Timeout` at this line in a loaded full-suite run). The
    // generous deadline holds the wall open so the fuel meter -- not the
    // clock -- decides the outcome, exactly as the fuel-refusal tests do
    // (CI-FIX-RPC-2); the 1M fuel grant still bounds the guest's work.
    let output = tool
        .call_with_deadline(&input, std::time::Duration::from_secs(10))
        .expect("run");
    assert_eq!(output, input);
}
