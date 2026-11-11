//! Envelope payloads are charged against the capability's byte budget.
//!
//! A transport dispatch that calls `call_with_payload` must not let a peer move
//! a large Infinity image for free, and the refusal must happen before the
//! provider runs.

use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::{Agent, Budget, Error};

struct Echo;

impl Provider for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn methods(&self) -> Vec<String> {
        vec!["echo".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::text("ok")))
    }
}

fn agent_with_bytes(max_bytes: u64) -> (Agent, active_rpc::CapHandle, active_rpc::LaneId) {
    let agent = Agent::with_secret([0x9a; 32]);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.budget.max_bytes = max_bytes;
    let cap = agent.mint(provider, 0, attrs).expect("mint");
    let lane = agent
        .create_lane("budget", Budget::default())
        .expect("lane");
    (agent, cap, lane)
}

#[test]
fn a_payload_over_the_byte_budget_is_refused_before_dispatch() {
    let (agent, cap, lane) = agent_with_bytes(1024);
    let error = agent
        .call_with_payload(lane, &cap, "echo", vec![Arg::text("small")], 4096)
        .expect_err("an oversized payload must be refused");
    assert!(matches!(error, Error::BudgetExceeded("byte")), "{error:?}");
    assert_eq!(agent.metrics().budget_exhaustions, 1);
}

#[test]
fn a_payload_within_the_byte_budget_is_charged_and_dispatched() {
    let (agent, cap, lane) = agent_with_bytes(8192);
    // Request and response both count (the response is 7 bytes of `Value::text`),
    // so three round trips of 2048 fit and the fourth is refused.
    for round in 0..3 {
        let promise = agent
            .call_with_payload(lane, &cap, "echo", Vec::new(), 2048)
            .unwrap_or_else(|error| panic!("round {round}: {error}"));
        agent.run();
        assert_eq!(promise.value().expect("value"), Value::text("ok"));
    }
    let error = agent
        .call_with_payload(lane, &cap, "echo", Vec::new(), 2048)
        .expect_err("the byte budget must be spent");
    assert!(matches!(error, Error::BudgetExceeded("byte")), "{error:?}");
}

/// A response is traffic through the capability too: a provider cannot return
/// more than the grant has left.
#[test]
fn a_response_larger_than_the_remaining_grant_is_refused() {
    struct Big;
    impl Provider for Big {
        fn name(&self) -> &'static str {
            "big"
        }
        fn methods(&self) -> Vec<String> {
            vec!["big".to_string()]
        }
        fn mutating(&self, _method: &str) -> bool {
            false
        }
        fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
            Ok(Response::Value(Value::text("x".repeat(4096))))
        }
    }

    let agent = Agent::with_secret([0x9b; 32]);
    let provider = agent.register(Box::new(Big)).expect("register provider");
    let cap = agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["big"]).with_budget(Budget {
                max_bytes: 64,
                ..Budget::default()
            }),
        )
        .expect("cap");
    let lane = agent
        .create_lane("egress", Budget::default())
        .expect("lane");
    let promise = agent.call(lane, &cap, "big", Vec::new()).expect("queued");
    agent.run();
    let error = promise.value().expect_err("the response does not fit");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}
