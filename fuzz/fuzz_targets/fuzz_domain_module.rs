#![no_main]

//! The module/domain provider: a peer's bytes and a peer's path.
//!
//! Invariants under test (I-4, I-6, I-8):
//!
//! 1. `install_canonical_image` is total over arbitrary bytes: a module or a
//!    `rpc/payload` refusal, never a panic.
//! 2. A call with a fuzzed path is refused or answered, never panics, and a
//!    refusal is a code from the closed catalogue.
//! 3. The provider never returns secret material for a redacting capability. The
//!    fixture for that is fixed (a fuzzed image almost never carries a secret).
//!    The oracle inspects answer bytes for the secret (RPC-26): formatting an
//!    answer cannot see inside a `Value::Module`, whose `Debug` prints only
//!    its byte count.
//!
//! 4. `evaluate` and `patch` are exercised, time-boxed (RPC-26): only a small
//!    installed image is evaluated, under a tight capability budget, and the
//!    fixed module proves the success branch is live on every input. An
//!    `evaluate` of an unbounded fuzzed image is slow enough to make the
//!    campaign useless, which is why the time-box — not the exclusion — is
//!    the fix.
//!
//! This is the highest-risk parser reachable from a peer (a module image and a
//! dotted path), and it had no target at all.
//!
//! Run with `cargo +nightly fuzz run fuzz_domain_module -- -runs=200000`.

use libfuzzer_sys::fuzz_target;

use active_rpc::cap::CapAttrs;
use active_rpc::domain::ModuleProvider;
use active_rpc::value::{Arg, Value};
use active_rpc::{Agent, Budget};

#[path = "common.rs"]
mod common;

/// Methods that answer without evaluating the module. `evaluate` and
/// `patch` are exercised separately, time-boxed (RPC-26): an `evaluate` of
/// a fuzzed image is slow enough to make the campaign useless if every input
/// is evaluated, so only a small image is evaluated, under a tight budget.
const PATH_METHODS: &[&str] = &["why", "impact", "subgraph"];
const VALUE_METHODS: &[&str] = &[
    "stats",
    "content_hash",
    "annotations",
    "provenance",
    "dependencies",
    "dependents",
];

/// Time-box for the `evaluate` / `patch` leg (RPC-26): only an image this
/// small is evaluated. The box keeps a pathological input from stalling the
/// campaign: a large image is never evaluated, and a small one is bounded
/// by the tight budget below.
const MAX_EVALUATE_IMAGE_BYTES: usize = 4_096;

/// A tight budget for the `evaluate` / `patch` leg (RPC-26): the evaluator's
/// node ceiling and wall clock are small and seeded, the rest is the default
/// grant, so the call itself is not refused before it reaches the provider.
/// A module over the node ceiling is refused with a catalogued code instead
/// of being evaluated.
fn evaluate_budget(data: &[u8]) -> Budget {
    let nodes = 64 + data.first().copied().unwrap_or(0) as u64 % 512;
    let wall_ms = 100 + data.get(1).copied().unwrap_or(0) as u64 % 400;
    Budget {
        max_nodes: nodes,
        max_wall_ms: wall_ms,
        max_value_size: 64 << 10,
        ..Budget::default()
    }
}

fuzz_target!(|data: &[u8]| {
    // Fixed positive control: a canonical image must install through the
    // parser, or the success branch below is dead (R-20 round 3, M4).
    let fixed = active_rpc::domain::module_from_source("[a]\nx = 1\n", "fixed")
        .expect("the fixed module");
    let fixed_image = active_infinity::encode(&fixed).expect("the fixed image encodes");
    // Installation is half the path: a provider that answers every call with
    // `rpc/provider` passed a control that only installed (R-20 round 6,
    // finding 8). The fixed module answers `stats`.
    {
        let mut provider = ModuleProvider::new();
        provider
            .install_canonical_image(&fixed_image)
            .expect("the canonical image installs");
        let agent = Agent::with_secret([0x32; 32]);
        let id = agent.register(Box::new(provider));
        let cap = agent
            .mint(id, 0, CapAttrs::new(&["stats", "evaluate", "patch"]))
            .expect("the fixed capability");
        let lane = agent
            .create_lane("fixed", Budget::default())
            .expect("the fixed lane");
        let promise = agent.call(lane, &cap, "stats", Vec::new()).expect("queued");
        agent.run();
        let value = promise.value().expect("the fixed module answers stats");
        assert!(
            matches!(value, Value::Map(_)),
            "the fixed stats answer is a map: {value:?}"
        );
        // RPC-26: the fixed module also proves the `evaluate` / `patch` leg
        // is live — a control that only ever refused would pass while
        // exercising nothing. Root evaluate answers a map, `a.x` is 1, a
        // patch to 2 sticks, and the next evaluate sees 2.
        let promise = agent
            .call(lane, &cap, "evaluate", Vec::new())
            .expect("queued");
        agent.run();
        let value = promise.value().expect("the fixed module evaluates");
        assert!(
            matches!(value, Value::Map(_)),
            "the fixed root evaluate answer is a map: {value:?}"
        );
        let promise = agent
            .call(
                lane,
                &cap,
                "evaluate",
                vec![Arg::Value(Value::path("a.x"))],
            )
            .expect("queued");
        agent.run();
        let value = promise.value().expect("a.x evaluates");
        assert_eq!(value, Value::Int(1), "a.x evaluates to 1: {value:?}");
        let promise = agent
            .call(
                lane,
                &cap,
                "patch",
                vec![
                    Arg::Value(Value::path("a.x")),
                    Arg::Value(Value::Int(2)),
                ],
            )
            .expect("queued");
        agent.run();
        let value = promise.value().expect("the fixed patch answers");
        assert!(
            matches!(value, Value::Module(_)),
            "a patch answer is module bytes: {value:?}"
        );
        let promise = agent
            .call(
                lane,
                &cap,
                "evaluate",
                vec![Arg::Value(Value::path("a.x"))],
            )
            .expect("queued");
        agent.run();
        let value = promise
            .value()
            .expect("a.x evaluates after the patch");
        assert_eq!(
            value,
            Value::Int(2),
            "a.x evaluates to 2 after the patch: {value:?}"
        );
    }

    if data.is_empty() {
        return;
    }

    // 1 and 2. The image parser is total, and a call through it answers or
    // refuses with a catalogued code.
    let mut provider = ModuleProvider::new();
    if let Ok(object) = provider.install_canonical_image(data) {
        let agent = Agent::with_secret([0x31; 32]);
        let id = agent.register(Box::new(provider));
        let cap = agent
            .mint(id, object, CapAttrs::new(active_rpc::MODULE_METHODS))
            .expect("mint over an installed module");
        let lane = agent
            .create_lane("domain", Budget::default())
            .expect("lane");
        let path = String::from_utf8_lossy(&data[..data.len().min(64)]).into_owned();
        let calls: Vec<(&str, Vec<Arg>)> = PATH_METHODS
            .iter()
            .map(|method| (*method, vec![Arg::Value(Value::path(path.as_str()))]))
            .chain(VALUE_METHODS.iter().map(|method| (*method, Vec::new())))
            .collect();
        for (method, args) in calls {
            match agent.call(lane, &cap, method, args) {
                Ok(promise) => {
                    agent.run();
                    if let Err(error) = promise.value() {
                        assert!(
                            active_rpc::error::ERROR_CODES.contains(&error.code()),
                            "an unexpected class for {method}: {error}"
                        );
                    }
                }
                Err(error) => assert!(
                    active_rpc::error::ERROR_CODES.contains(&error.code()),
                    "an unexpected refusal class for {method}: {error}"
                ),
            }
        }
    }

    // 1b. RPC-26: `evaluate` and `patch` on the installed image — the two
    // entry points the oracle never reached. Time-boxed, as the audit's
    // recommendation requires: only a small image is evaluated, under a
    // tight capability budget (small node ceiling, short wall clock), so a
    // pathological input refuses quickly instead of stalling the campaign.
    // A refusal is a catalogued code; an answer is checked like every
    // other. Root evaluate, path evaluate, a patch at the fuzzed path with
    // a fuzzed integer literal, then evaluate again so a patch that
    // corrupts the module is seen by the next call. The literal is an
    // integer on purpose: a text replacement on a secret-bearing module is
    // refused by the provider, which would leave the write path exercised
    // only through the refusal branch.
    if data.len() <= MAX_EVALUATE_IMAGE_BYTES {
        let mut provider = ModuleProvider::new();
        if let Ok(object) = provider.install_canonical_image(data) {
            let agent = Agent::with_secret([0x31; 32]);
            let id = agent.register(Box::new(provider));
            let cap = agent
                .mint(
                    id,
                    object,
                    CapAttrs::new(&["evaluate", "patch"])
                        .with_budget(evaluate_budget(data)),
                )
                .expect("mint over an installed module");
            let lane = agent
                .create_lane("evaluate", Budget::default())
                .expect("lane");
            let path = String::from_utf8_lossy(&data[..data.len().min(64)]).into_owned();
            let literal = Value::Int(i64::from(data.first().copied().unwrap_or(0)));
            let calls: Vec<(&str, Vec<Arg>)> = vec![
                ("evaluate", Vec::new()),
                ("evaluate", vec![Arg::Value(Value::path(path.as_str()))]),
                (
                    "patch",
                    vec![
                        Arg::Value(Value::path(path.as_str())),
                        Arg::Value(literal),
                    ],
                ),
                ("evaluate", vec![Arg::Value(Value::path(path.as_str()))]),
            ];
            for (method, args) in calls {
                match agent.call(lane, &cap, method, args) {
                    Ok(promise) => {
                        agent.run();
                        if let Err(error) = promise.value() {
                            assert!(
                                active_rpc::error::ERROR_CODES.contains(&error.code()),
                                "an unexpected class for {method}: {error}"
                            );
                        }
                    }
                    Err(error) => assert!(
                        active_rpc::error::ERROR_CODES.contains(&error.code()),
                        "an unexpected refusal class for {method}: {error}"
                    ),
                }
            }
        }
    }

    // 2. A second image parsed from the same bytes, then a fuzzed path through
    //    it: the path is peer input too, and the lookup is where an index bug
    //    would surface.
    let source = String::from_utf8_lossy(data);
    let mut provider = ModuleProvider::new();
    if let Ok(object) = provider.install_canonical_image(source.as_bytes()) {
        let agent = Agent::with_secret([0x32; 32]);
        let id = agent.register(Box::new(provider));
        let cap = agent
            .mint(id, object, CapAttrs::new(&["why"]))
            .expect("mint");
        let lane = agent
            .create_lane("source", Budget::default())
            .expect("lane");
        let path = format!("[{}", String::from_utf8_lossy(&data[..data.len().min(32)]));
        match agent.call(lane, &cap, "why", vec![Arg::Value(Value::path(path))]) {
            Ok(promise) => {
                agent.run();
                if let Err(error) = promise.value() {
                    assert!(
                        active_rpc::error::ERROR_CODES.contains(&error.code()),
                        "an unexpected class for why: {error}"
                    );
                }
            }
            Err(error) => assert!(
                active_rpc::error::ERROR_CODES.contains(&error.code()),
                "an unexpected refusal class for why: {error}"
            ),
        }
    }

    // 3. A redacting capability never returns secret material.
    const CANARY: &str = "fuzz-canary-secret";
    let source = format!("[app]\ntoken = secret(\"{CANARY}\")\nport = 8080\n");
    let module = active_rpc::domain::module_from_source(&source, "canary").expect("fixture");
    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let agent = Agent::with_secret([0x33; 32]);
    let id = agent.register(Box::new(provider));
    let redacted: Vec<&str> = PATH_METHODS
        .iter()
        .chain(VALUE_METHODS.iter())
        .copied()
        // RPC-26: the redaction oracle also watches `evaluate` and `patch`
        // — the two methods whose answers it could not see at all (`patch`
        // answers module bytes; `evaluate` can return secret-derived text).
        // `patch` runs last: it mutates the fixture, and nothing after it
        // depends on the pre-patch module.
        .chain(["evaluate", "patch"])
        .collect();
    let cap = agent
        .mint(id, object, CapAttrs::new(&redacted).redacted())
        .expect("mint");
    let lane = agent
        .create_lane("redact", Budget::default())
        .expect("lane");
    for method in redacted {
        let args = if method == "evaluate" {
            Vec::new()
        } else if method == "patch" {
            vec![
                Arg::Value(Value::path("app.port")),
                Arg::Value(Value::Int(9090)),
            ]
        } else if PATH_METHODS.contains(&method) {
            vec![Arg::Value(Value::path("app"))]
        } else {
            Vec::new()
        };
        let promise = match agent.call(lane, &cap, method, args) {
            Ok(promise) => promise,
            Err(error) => {
                assert!(
                    active_rpc::error::ERROR_CODES.contains(&error.code()),
                    "an unexpected refusal class for {method}: {error}"
                );
                continue;
            }
        };
        agent.run();
        // RPC-26: inspect the answer for the secret instead of formatting
        // it — `Value::Module`'s `Debug` prints only the byte count, so the
        // old `format!("{value:?}")` check could never see a secret inside
        // a `subgraph` / `patch` module answer. A refusal is text, so the
        // formatted check still applies to it.
        match promise.value() {
            Ok(value) => assert!(
                !common::answer_leaks_secret(&value, CANARY),
                "a redacting {method} answer carried the secret: {value:?}"
            ),
            Err(error) => assert!(
                !format!("{error}").contains(CANARY),
                "a redacting {method} refusal carried the secret: {error}"
            ),
        };
    }
});
