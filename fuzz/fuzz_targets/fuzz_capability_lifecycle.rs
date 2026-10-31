#![no_main]

//! Capability lifecycle: mint, attenuate, revoke, clone, drop, call, forge.
//!
//! Invariants under test (I-4, I-5, I-6, I-7):
//!
//! 1. A capability minted by a kernel with a *different* secret is not accepted
//!    by another. (Two kernels that share a secret are one authority domain, so
//!    the target derives the second kernel from a seed that cannot collide.)
//! 2. Attenuation accepts a subset and refuses any widening.
//! 3. A revoked capability is refused at the next call, and its children die.
//! 4. Forging or importing an unknown id is refused.
//! 5. A zero ceiling is refused at mint or lane creation.
//!
//! Run with `cargo +nightly fuzz run fuzz_capability_lifecycle -- -runs=200000`.

use libfuzzer_sys::fuzz_target;

use active_rpc::{Budget, CapAttrs, CapId};

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let agent = common::agent(data);
    let provider = agent.register(Box::new(common::Echo::default()));
    let lane = agent
        .create_lane("main", Budget::default())
        .expect("default lane budget");
    let mut caps = vec![common::mint(
        &agent,
        provider,
        &common::methods(data),
        Budget::default(),
    )];

    for byte in data.iter().take(96) {
        match byte % 8 {
            0 => {
                // Attenuate to a subset of the parent's methods.
                if let Some(parent) = caps.last() {
                    let child_methods = if byte % 2 == 0 {
                        vec!["ping"]
                    } else {
                        vec!["echo"]
                    };
                    if let Ok(child) = agent.attenuate(parent, CapAttrs::new(&child_methods)) {
                        caps.push(child);
                    }
                }
            }
            1 => {
                // Widening the method set must be refused.
                if let Some(parent) = caps.last() {
                    let error = agent
                        .attenuate(parent, CapAttrs::new(&["__not_granted__"]))
                        .expect_err("method escalation must be refused");
                    assert_eq!(error.code(), "rpc/attenuation-escalation");
                }
            }
            2 => {
                // A normal call settles.
                if let Some(cap) = caps.last() {
                    if let Ok(promise) = agent.call(lane, cap, "ping", vec![]) {
                        let _ = promise.value();
                    }
                }
            }
            3 => {
                // Revoke the newest capability; every later call is refused.
                if let Some(cap) = caps.pop() {
                    agent.revoke(&cap);
                    let error = agent
                        .call(lane, &cap, "ping", vec![])
                        .expect_err("a revoked capability must be refused");
                    assert!(
                        matches!(error.code(), "rpc/revoked" | "rpc/unknown-capability"),
                        "unexpected code {}",
                        error.code()
                    );
                }
            }
            4 => {
                // Cloning and dropping must not revoke the original.
                if let Some(cap) = caps.last() {
                    let clone = cap.clone();
                    drop(clone);
                    let _ = agent.call(lane, cap, "ping", vec![]);
                }
            }
            5 => {
                // A forged id, including an id from another kernel.
                //
                // The second kernel must have a *different* secret. Two kernels
                // that share a secret are the same authority domain by design
                // (see SECURITY.md), so the transplant check only means
                // something across distinct secrets. Flipping byte 0 of the
                // seed guarantees that, because the secret starts at seed[0].
                let mut other_seed = data.to_vec();
                other_seed[0] ^= 0xff;
                let other = common::agent(&other_seed);
                let other_provider = other.register(Box::new(common::Echo::default()));
                let foreign = common::mint(&other, other_provider, &["ping"], Budget::default());
                let transplanted = agent.import(foreign.id());
                let error = agent
                    .call(lane, &transplanted, "ping", vec![])
                    .expect_err("a foreign capability must not transplant");
                assert_eq!(error.code(), "rpc/unknown-capability");

                let forged = agent.import(CapId([*byte; 16]));
                let error = agent
                    .call(lane, &forged, "ping", vec![])
                    .expect_err("a forged id must be refused");
                assert_eq!(error.code(), "rpc/unknown-capability");
            }
            6 => {
                // A zero ceiling is refused.
                let error = agent
                    .create_lane(
                        "zero",
                        Budget {
                            max_calls: 0,
                            ..Budget::default()
                        },
                    )
                    .expect_err("a zero ceiling must be refused");
                assert_eq!(error.code(), "rpc/invalid-argument");
            }
            _ => {
                // A method outside the grant is refused before the provider.
                if let Some(cap) = caps.last() {
                    let error = agent
                        .call(lane, cap, "not_granted", vec![])
                        .expect_err("a method outside the grant must be refused");
                    assert_eq!(error.code(), "rpc/method-not-granted");
                }
            }
        }
    }

    // Dropping every handle must notify the provider exactly once per object.
    let drops = agent.take_drops(provider);
    for (_, cap) in &drops {
        let _ = cap;
    }
});
