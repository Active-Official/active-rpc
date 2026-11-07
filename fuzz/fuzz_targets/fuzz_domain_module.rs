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

/// Methods that answer without evaluating the module (an `evaluate` of a
/// fuzzed image is slow enough to make the campaign useless).
const PATH_METHODS: &[&str] = &["why", "impact", "subgraph"];
const VALUE_METHODS: &[&str] = &[
    "stats",
    "content_hash",
    "annotations",
    "provenance",
    "dependencies",
    "dependents",
];

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
            .mint(id, 0, CapAttrs::new(&["stats"]))
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
        .collect();
    let cap = agent
        .mint(id, object, CapAttrs::new(&redacted).redacted())
        .expect("mint");
    let lane = agent
        .create_lane("redact", Budget::default())
        .expect("lane");
    for method in redacted {
        let args = if PATH_METHODS.contains(&method) {
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
        let answer = match promise.value() {
            Ok(value) => format!("{value:?}"),
            Err(error) => format!("{error}"),
        };
        assert!(
            !answer.contains(CANARY),
            "a redacting {method} answer carried the secret: {answer}"
        );
    }
});
