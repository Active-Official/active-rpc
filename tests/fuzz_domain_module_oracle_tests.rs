//! RPC-26 — the `fuzz_domain_module` oracle was blind for modules.
//!
//! Two defects, one finding (round 1, R-20; verified CONFIRMED by W1):
//!
//! 1. `fuzz/fuzz_targets/fuzz_domain_module.rs` never called `evaluate` or
//!    `patch` — the highest-risk entry points (the evaluator and the mutating
//!    write path) were invisible to the fuzzer. Only `why` / `impact` /
//!    `subgraph` + value methods were exercised.
//! 2. Its redaction oracle formatted answers with `format!("{value:?}")`.
//!    `Value::Module`'s `Debug` prints only `Module(<N bytes>)` — never the
//!    bytes — so a secret leaked inside a `subgraph` / `patch` module answer
//!    could not be seen by the check. The oracle must inspect the raw module
//!    bytes for secret material instead of formatting them.
//!
//! The static tests below are the regression gate for (1) and (2): they fail
//! on the unfixed target and pass once the oracle calls `evaluate` / `patch`
//! and checks answers with the byte-inspecting helper. The
//! `formatted_module_debug_cannot_see_a_planted_secret` test is the
//! demonstration of the mechanism behind (2): it passes on any tree, because
//! it shows the old formatted check missing a leak the byte scan catches.
//! The `fixed_module_evaluate_and_patch_roundtrip` test is the control-validity
//! probe for the fixed positive control the target adds: it proves, through
//! the real `Agent`, that `evaluate` and `patch` on the fixed module answer
//! the way the control asserts (root evaluates to a map, `a.x` is `1`, a
//! patch to `2` sticks and the next evaluate sees `2`).

use std::path::Path;

use active_rpc::cap::CapAttrs;
use active_rpc::domain::ModuleProvider;
use active_rpc::value::{Arg, Value};
use active_rpc::{Agent, Budget};

/// The oracle helper itself, compiled straight from the fuzz target's
/// shared helpers — the fuzz crate has no library target, so this is the
/// same `#[path]` inclusion the targets use. These tests pin the helper's
/// contract (see the `fuzz/tests` note in the record: `cargo test` in the
/// fuzz crate cannot link the `#![no_main]` fuzz bins, so the helper's
/// tests live here, where they run).
#[path = "../fuzz/fuzz_targets/common.rs"]
mod common;

use common::answer_leaks_secret;

/// The fuzz target under test, read from the repo checkout.
fn fuzz_target_source() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/fuzz_targets/fuzz_domain_module.rs");
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

#[test]
fn oracle_calls_evaluate_and_patch() {
    let source = fuzz_target_source();
    // Whitespace-free, so a call-table entry split over lines still
    // matches. Either a direct `agent.call(lane, &cap, "<method>", …)` site
    // or a call-table entry `("<method>", …)` — both go through
    // `agent.call`. (A bare `CapAttrs::new(&["evaluate", "patch"])` does not
    // match: it grants the methods without calling them.)
    let flat: String = source.chars().filter(|ch| !ch.is_whitespace()).collect();
    let calls = |method: &str| {
        flat.contains(&format!(",\"{method}\",")) || flat.contains(&format!("(\"{method}\","))
    };
    assert!(
        calls("evaluate"),
        "RPC-26: fuzz_domain_module never calls `evaluate` — the evaluator is invisible to the fuzzer"
    );
    assert!(
        calls("patch"),
        "RPC-26: fuzz_domain_module never calls `patch` — the mutating write path is invisible to the fuzzer"
    );
}

#[test]
fn oracle_inspects_module_bytes_for_secrets() {
    let source = fuzz_target_source();
    assert!(
        source.contains("answer_leaks_secret"),
        "RPC-26: the redaction oracle must inspect answer bytes for secret material instead of formatting them"
    );
}

#[test]
fn formatted_module_debug_cannot_see_a_planted_secret() {
    const CANARY: &str = "fuzz-canary-secret";
    // A module answer whose bytes carry the secret verbatim: exactly what a
    // leaking `subgraph` / `patch` reply would look like.
    let mut bytes = b"canonical-prefix".to_vec();
    bytes.extend_from_slice(CANARY.as_bytes());
    bytes.extend_from_slice(b"canonical-suffix");
    let value = Value::Module(bytes.clone());

    // The old oracle: format the answer and look for the secret in the text.
    let formatted = format!("{value:?}");
    assert!(
        !formatted.contains(CANARY),
        "the formatted answer unexpectedly shows the secret: {formatted}"
    );

    // The fixed oracle: scan the raw bytes.
    let leaked = bytes
        .windows(CANARY.len())
        .any(|window| window == CANARY.as_bytes());
    assert!(leaked, "the byte scan must see the planted secret");
}

/// Control-validity probe for the fixed positive control the target adds/// (RPC-26): `evaluate` / `patch` through the real `Agent` on the fixed
/// module `[a]\nx = 1\n`.
///
/// This exercises production code, which was already correct — it passes on
/// the unfixed tree too. Its job is to prove the control's assertions are
/// sound (the paths resolve, the values are what the control claims), so a
/// green fuzz control means the oracle really reached `evaluate` / `patch`
/// and not a refusal-only path.
#[test]
fn fixed_module_evaluate_and_patch_roundtrip() {
    let fixed =
        active_rpc::domain::module_from_source("[a]\nx = 1\n", "fixed").expect("the fixed module");
    let fixed_image = active_infinity::encode(&fixed).expect("the fixed image encodes");
    let mut provider = ModuleProvider::new();
    provider
        .install_canonical_image(&fixed_image)
        .expect("the canonical image installs");
    let agent = Agent::with_secret([0x32; 32]);
    let id = agent
        .register(Box::new(provider))
        .expect("register provider");
    let cap = agent
        .mint(id, 0, CapAttrs::new(&["stats", "evaluate", "patch"]))
        .expect("the fixed capability");
    let lane = agent
        .create_lane("fixed", Budget::default())
        .expect("the fixed lane");

    // Root evaluate: the whole module evaluates to a record.
    let promise = agent
        .call(lane, &cap, "evaluate", Vec::new())
        .expect("evaluate queues");
    agent.run();
    let value = promise.value().expect("the fixed module evaluates");
    assert!(
        matches!(value, Value::Map(_)),
        "the fixed root evaluate answer is a map: {value:?}"
    );

    // Path evaluate: `a.x` is `1`.
    let promise = agent
        .call(lane, &cap, "evaluate", vec![Arg::Value(Value::path("a.x"))])
        .expect("path evaluate queues");
    agent.run();
    let value = promise.value().expect("a.x evaluates");
    assert_eq!(value, Value::Int(1), "a.x evaluates to 1: {value:?}");

    // Patch `a.x` to `2`: the reply is the patched cone as module bytes.
    let promise = agent
        .call(
            lane,
            &cap,
            "patch",
            vec![Arg::Value(Value::path("a.x")), Arg::Value(Value::Int(2))],
        )
        .expect("patch queues");
    agent.run();
    let value = promise.value().expect("patch answers");
    assert!(
        matches!(value, Value::Module(_)),
        "a patch answer is module bytes: {value:?}"
    );

    // The patch sticks: the next evaluate sees `2`.
    let promise = agent
        .call(lane, &cap, "evaluate", vec![Arg::Value(Value::path("a.x"))])
        .expect("post-patch evaluate queues");
    agent.run();
    let value = promise.value().expect("a.x evaluates after the patch");
    assert_eq!(
        value,
        Value::Int(2),
        "a.x evaluates to 2 after the patch: {value:?}"
    );
}

// ---------------------------------------------------------------------------
// `answer_leaks_secret` contract (RPC-26): the helper the redaction oracle
// uses instead of formatting answers. Text is searched as text, module
// bytes are searched as bytes (the case the old check was blind to),
// containers recurse, and the `Secret` marker — which carries no content —
// never counts as a leak.
// ---------------------------------------------------------------------------

#[test]
fn helper_text_answer_carrying_the_secret_leaks() {
    const CANARY: &str = "fuzz-canary-secret";
    assert!(answer_leaks_secret(
        &Value::Text(format!("token={CANARY}")),
        CANARY
    ));
}

#[test]
fn helper_text_answer_without_the_secret_is_clean() {
    assert!(!answer_leaks_secret(
        &Value::Text("port=8080".to_string()),
        "fuzz-canary-secret"
    ));
}

#[test]
fn helper_module_bytes_carrying_the_secret_leak() {
    const CANARY: &str = "fuzz-canary-secret";
    // The case the formatted oracle was blind to: the bytes hold the secret
    // verbatim, and `format!("{value:?}")` would print only the byte count.
    let mut bytes = b"canonical-prefix".to_vec();
    bytes.extend_from_slice(CANARY.as_bytes());
    bytes.extend_from_slice(b"canonical-suffix");
    let value = Value::Module(bytes);
    assert!(
        !format!("{value:?}").contains(CANARY),
        "the old formatted check misses this leak by construction"
    );
    assert!(answer_leaks_secret(&value, CANARY));
}

#[test]
fn helper_module_bytes_without_the_secret_are_clean() {
    assert!(!answer_leaks_secret(
        &Value::Module(b"canonical-prefix-suffix".to_vec()),
        "fuzz-canary-secret"
    ));
}

#[test]
fn helper_nested_answer_recurses_into_containers() {
    const CANARY: &str = "fuzz-canary-secret";
    let mut map = std::collections::BTreeMap::new();
    map.insert(
        "cone".to_string(),
        Value::List(vec![
            Value::Int(1),
            Value::Module(format!("x{CANARY}y").into_bytes()),
        ]),
    );
    assert!(answer_leaks_secret(&Value::Map(map), CANARY));
}

#[test]
fn helper_secret_marker_is_not_a_leak() {
    // `Value::Secret` is a marker, never content.
    assert!(!answer_leaks_secret(&Value::Secret, "fuzz-canary-secret"));
}

#[test]
fn helper_empty_secret_never_leaks() {
    assert!(!answer_leaks_secret(
        &Value::Module(b"anything".to_vec()),
        ""
    ));
    assert!(!answer_leaks_secret(&Value::Text("anything".into()), ""));
}
