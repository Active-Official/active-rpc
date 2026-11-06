//! R-14 round 3: a `memory.grow` inside `run` is charged against the grant, and
//! a module argument that carries a structural secret never reaches the guest.

#![cfg(feature = "wasm-tools")]

use active_rpc::value::{Arg, Call, Value};
use active_rpc::wasm_tool::{WasmHostPolicy, WasmLimits, WasmTool};
use active_rpc::{Budget, Provider, Response};

/// A guest that grows its memory by 233 pages (from one page to 234) and then
/// returns 0. Whether the growth is affordable is the only variable.
const GROW: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "run") (param i32) (result i32)
    (drop (memory.grow (i32.const 233)))
    (i32.const 0)))
"#;

/// A guest with the same memory that never grows it: the control for the grow.
const PLAIN: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "run") (param i32) (result i32)
    (i32.const 0)))
"#;

/// A guest that echoes its input area.
const ECHO: &str = r#"
(module
  (memory (export "memory") 2)
  (func (export "run") (param i32) (result i32) (local.get 0)))
"#;

fn tool(source: &str, limits: WasmLimits) -> WasmTool {
    let policy = WasmHostPolicy {
        accept_wat: true,
        ..WasmHostPolicy::default()
    };
    WasmTool::from_bytes_with_policy(source.as_bytes(), limits, policy).expect("compiles")
}

fn run(tool: &mut WasmTool, input: &str, wall_ms: u64) -> active_rpc::Result<Response> {
    let mut call = Call::new("run", vec![Arg::text(input)]);
    call.budget = Budget {
        max_wall_ms: wall_ms,
        ..Budget::default()
    };
    call.now_ms = 1;
    tool.invoke(0, &call)
}

/// A `memory.grow` is paid for out of the guest's own fuel.
///
/// The observation, and the reason round 3's M-1 is not a defect: the same guest
/// is refused `wasm/fuel` under a 30 000-fuel grant (which covers its 234 pages
/// at that rate but leaves nothing for the instructions that asked for them) and
/// runs under a 1e6-fuel grant, while a guest that does not grow runs under the
/// small grant. The store limiter is the bound; the engine is the accounting
/// (R-14 round 3, M-1 — refuted with this test).
#[test]
fn a_memory_grow_is_paid_for_out_of_the_guest_fuel() {
    let small = || {
        tool(
            GROW,
            WasmLimits {
                fuel: 30_000,
                ..WasmLimits::default()
            },
        )
    };
    let error = run(&mut small(), "", 1_000).expect_err("the growth leaves no fuel to ask with");
    assert_eq!(
        error.provider_code(),
        Some("wasm/fuel"),
        "an unaffordable growth is a fuel refusal: {error}"
    );

    // The control with the same grant and no growth: it runs, so the refusal is
    // the growth and not the grant.
    let mut plain = tool(
        PLAIN,
        WasmLimits {
            fuel: 30_000,
            ..WasmLimits::default()
        },
    );
    let response =
        run(&mut plain, "", 1_000).expect("the same grant runs a guest that does not grow");
    assert!(matches!(response, Response::Value(Value::Text(_))));

    // And the growth itself is affordable under a grant that covers it.
    let mut large = tool(
        GROW,
        WasmLimits {
            fuel: 1_000_000,
            ..WasmLimits::default()
        },
    );
    let response = run(&mut large, "", 1_000).expect("the growth is affordable");
    assert!(matches!(response, Response::Value(Value::Text(_))));
}

/// A module image can carry a structural secret, which the guest would read as
/// plain input and could return mangled into an opaque blob. The rule "a secret
/// is not a wasm argument" applies to that shape too (R-14 round 3, L-3).
#[test]
fn a_secret_bearing_module_argument_is_refused() {
    use active_infinity::{encode, InfinityModule, Inode};

    let mut module = InfinityModule::new();
    let secret = module.push(Inode::Secret(active_infinity::SecretBytes::new(b"canary")));
    let key = module.push(Inode::Str("password".to_string()));
    let root = module.push(Inode::Table {
        fields: vec![("k".to_string(), key), ("v".to_string(), secret)],
    });
    module.set_root(Some(root));
    let image = encode(&module).expect("encode");

    let mut guest = tool(ECHO, WasmLimits::default());
    let mut call = Call::new("run", vec![Arg::Value(Value::Module(image))]);
    call.budget = Budget::default();
    call.now_ms = 1;
    let error = guest
        .invoke(0, &call)
        .expect_err("a secret-bearing image is not an argument");
    assert_eq!(error.code(), "rpc/tool-policy", "{error}");

    // An opaque module argument (not an image) still reaches the guest: the rule
    // is about structural secrets, not about binary inputs.
    let mut guest = tool(ECHO, WasmLimits::default());
    let mut call = Call::new("run", vec![Arg::Value(Value::Module(vec![0x41, 0x49]))]);
    call.budget = Budget::default();
    call.now_ms = 1;
    guest
        .invoke(0, &call)
        .expect("opaque bytes are ordinary input");
}
