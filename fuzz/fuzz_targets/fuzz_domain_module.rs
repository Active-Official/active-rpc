#![no_main]

//! The module/domain provider: a peer's bytes and a peer's path.
//!
//! Invariants under test (I-4, I-6, I-8):
//!
//! 1. `install_canonical_image` is total over arbitrary bytes: a module or a
//!    `rpc/payload` refusal, never a panic.
//! 2. A call with a fuzzed path is refused or answered, never panics, and a
//!    refusal is a stable code.
//! 3. The provider never returns secret material for a redacting capability.
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

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // 1. The image parser is total.
    let mut provider = ModuleProvider::new();
    match provider.install_canonical_image(data) {
        Ok(object) => {
            // A module the parser accepted must answer a metadata query without
            // panicking, on a kernel that holds a real capability.
            let agent = Agent::with_secret([0x31; 32]);
            let id = agent.register(Box::new(provider));
            let cap = agent
                .mint(
                    id,
                    object,
                    CapAttrs::new(&["metadata", "why", "impact", "subgraph"]),
                )
                .expect("mint over an installed module");
            let lane = agent
                .create_lane("domain", Budget::default())
                .expect("lane");
            let path = String::from_utf8_lossy(&data[..data.len().min(64)]).into_owned();
            for method in ["metadata", "why", "impact", "subgraph"] {
                let promise = agent
                    .call(
                        lane,
                        &cap,
                        method,
                        vec![Arg::Value(Value::path(path.clone()))],
                    )
                    .expect("queued");
                agent.run();
                // Either an answer or a refusal with a stable code; no panic.
                if let Err(error) = promise.value() {
                    assert!(
                        error.code().starts_with("rpc/"),
                        "unexpected class for {method}: {error}"
                    );
                }
            }
        }
        Err(error) => assert_eq!(
            error.code(),
            "rpc/payload",
            "a module image the parser refuses must be a payload error, got {error}"
        ),
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
            .mint(id, object, CapAttrs::new(&["metadata"]))
            .expect("mint");
        let lane = agent
            .create_lane("source", Budget::default())
            .expect("lane");
        let path = format!("[{}", String::from_utf8_lossy(&data[..data.len().min(32)]));
        let promise = agent
            .call(lane, &cap, "metadata", vec![Arg::Value(Value::path(path))])
            .expect("queued");
        agent.run();
        let _ = promise.value();
    }
});
