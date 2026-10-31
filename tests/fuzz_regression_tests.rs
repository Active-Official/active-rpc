//! Regression tests for failures found by the nightly fuzz lane.
//!
//! Each test reproduces a committed `fuzz/corpus` input through the public API,
//! so a regression fails in `cargo test` long before a nightly campaign would
//! find it again.

use active_rpc::cap::{CapAttrs, CapId};
use active_rpc::kernel::Provider;
use active_rpc::value::{Call, Response, Value};
use active_rpc::{Agent, Budget, CapHandle};

struct Echo;

impl Provider for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn methods(&self) -> Vec<String> {
        vec!["ping".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::text("pong")))
    }
}

/// The exact input libFuzzer wrote to
/// `fuzz/artifacts/fuzz_capability_lifecycle/crash-680d7cf6...` on
/// 2026-10-31, also committed as
/// `fuzz/corpus/fuzz_capability_lifecycle/c10-transplant-distinct-secret.bin`.
///
/// The first 32 bytes are all `0x06`, so cycling the seed produces the same
/// secret as a one-byte seed of `0x06`. The target used to build its "other"
/// kernel from `byte + 1` of an arbitrary position in this input, which for
/// this input expanded back to `[0x06; 32]`: both kernels then derived the same
/// id at serial 0 and the transplant assertion failed on a *local* capability.
/// The target now flips seed byte 0, which provably changes `secret[0]`.
#[test]
fn the_nightly_crash_input_is_refused_because_the_other_secret_differs() {
    let input: [u8; 94] = [
        6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, //
        6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, //
        6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 5, 255, //
        6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, //
        6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, //
        6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 74, 139, 10, 85, 39, 61,
    ];

    // The old harness bug in one line: the main secret and the "other" secret
    // were byte-for-byte equal for this input.
    assert_eq!(expand(&input), expand(&[6]));

    let agent = common_agent(&input);
    let provider = agent.register(Box::new(Echo));
    let mut other_seed = input.to_vec();
    other_seed[0] ^= 0xff;
    assert_ne!(expand(&input), expand(&other_seed));

    let other = common_agent(&other_seed);
    let other_provider = other.register(Box::new(Echo));
    let foreign = mint(&other, other_provider);
    let transplanted = agent.import(foreign.id());
    let lane = agent
        .create_lane("main", Budget::default())
        .expect("lane budget");
    let error = agent
        .call(lane, &transplanted, "ping", vec![])
        .expect_err("a capability from a kernel with another secret must not transplant");
    assert_eq!(error.code(), "rpc/unknown-capability");

    // The local capability the id collided with still works.
    let own = mint(&agent, provider);
    let promise = agent.call(lane, &own, "ping", vec![]).expect("own call");
    agent.run();
    assert_eq!(promise.value().expect("settled"), Value::text("pong"));
}

/// Two kernels that share a secret are one authority domain: they derive the
/// same id for the same serial. This is a property of the design (a `CapId` is
/// unforgeable because the secret is), and it is why the fuzz target must use
/// distinct secrets for the transplant invariant. Documented here so a future
/// change cannot quietly "fix" the fuzz assertion by weakening the derivation.
#[test]
fn kernels_that_share_a_secret_derive_the_same_id_for_the_same_serial() {
    let first = common_agent(&[0x06]);
    let second = common_agent(&[0x06]);
    let first_provider = first.register(Box::new(Echo));
    let second_provider = second.register(Box::new(Echo));
    let a = mint(&first, first_provider);
    let b = mint(&second, second_provider);

    assert_eq!(a.id(), b.id());
    assert_eq!(a.id(), CapId::derive(&expand(&[0x06]), 0, None));

    // A different secret never collides for the first serial.
    let third = common_agent(&[0x07]);
    let third_provider = third.register(Box::new(Echo));
    let c = mint(&third, third_provider);
    assert_ne!(a.id(), c.id());
}

fn expand(seed: &[u8]) -> [u8; 32] {
    let mut secret = [0u8; 32];
    for (slot, byte) in secret.iter_mut().zip(seed.iter().cycle()) {
        *slot = *byte;
    }
    secret
}

fn common_agent(seed: &[u8]) -> Agent {
    Agent::with_secret(expand(seed))
}

fn mint(agent: &Agent, provider: active_rpc::ProviderId) -> CapHandle {
    agent
        .mint(provider, 0, CapAttrs::new(&["ping"]))
        .expect("mint")
}
