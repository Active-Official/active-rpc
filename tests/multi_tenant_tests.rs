//! Multi-tenant cross-talk: independent agents, capabilities and budgets must
//! never see or spend each other's authority, even when their work is
//! interleaved in one process.

use active_rpc::cap::CapAttrs;
use active_rpc::kernel::{Event, Provider};
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

    fn invoke(&mut self, _object: u64, call: &Call) -> active_rpc::Result<Response> {
        let value = call
            .args
            .iter()
            .find_map(|arg| match arg {
                Arg::Value(value) => Some(value.clone()),
                _ => None,
            })
            .unwrap_or(Value::Null);
        Ok(Response::Value(value))
    }
}

fn tenant(secret: u8) -> (Agent, active_rpc::CapHandle, active_rpc::LaneId) {
    let agent = Agent::with_secret([secret; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let lane = agent
        .create_lane("tenant", Budget::default())
        .expect("lane");
    (agent, cap, lane)
}

fn call_text(
    agent: &Agent,
    lane: active_rpc::LaneId,
    cap: &active_rpc::CapHandle,
    text: &str,
) -> active_rpc::Result<Value> {
    let promise = agent.call(lane, cap, "echo", vec![Arg::text(text)])?;
    agent.run();
    promise.value()
}

#[test]
fn a_capability_from_one_agent_is_unknown_to_another() {
    let (first, first_cap, first_lane) = tenant(0x11);
    let (second, _, second_lane) = tenant(0x22);
    // The same opaque id means nothing in the other tenant.
    let borrowed = second.import(first_cap.id());
    let error = call_text(&second, second_lane, &borrowed, "cross")
        .expect_err("a foreign capability must be refused");
    assert_eq!(error.code(), "rpc/unknown-capability");
    // The owner still works.
    assert_eq!(
        call_text(&first, first_lane, &first_cap, "own").expect("own call"),
        Value::Text("own".to_string())
    );
}

#[test]
fn budgets_are_charged_per_capability() {
    let agent = Agent::with_secret([0x33; 32]);
    let provider = agent.register(Box::new(Echo));
    let mut tight = CapAttrs::new(&["echo"]);
    tight.budget.max_calls = 2;
    let tight_cap = agent.mint(provider, 0, tight).expect("tight cap");
    let loose_cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("loose cap");
    let lane = agent
        .create_lane("tenant", Budget::default())
        .expect("lane");

    for index in 0..2 {
        call_text(&agent, lane, &tight_cap, &format!("tight-{index}")).expect("within budget");
    }
    let error = call_text(&agent, lane, &tight_cap, "over").expect_err("budget must refuse");
    assert_eq!(error.code(), "rpc/budget-exceeded");
    // The other capability on the same provider is untouched.
    assert_eq!(
        call_text(&agent, lane, &loose_cap, "loose").expect("loose call"),
        Value::Text("loose".to_string())
    );
}

#[test]
fn interleaved_lanes_keep_their_own_results() {
    let agent = Agent::with_secret([0x44; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let first = agent.create_lane("first", Budget::default()).expect("lane");
    let second = agent
        .create_lane("second", Budget::default())
        .expect("lane");

    let first_promise = agent
        .call(first, &cap, "echo", vec![Arg::text("one")])
        .expect("first");
    let second_promise = agent
        .call(second, &cap, "echo", vec![Arg::text("two")])
        .expect("second");
    agent.run();
    assert_eq!(
        first_promise.value().expect("first value"),
        Value::Text("one".into())
    );
    assert_eq!(
        second_promise.value().expect("second value"),
        Value::Text("two".into())
    );
}

#[test]
fn event_logs_carry_only_the_local_tenants_capabilities() {
    let (first, first_cap, first_lane) = tenant(0x55);
    let (second, second_cap, second_lane) = tenant(0x66);
    call_text(&first, first_lane, &first_cap, "a").expect("a");
    call_text(&second, second_lane, &second_cap, "b").expect("b");

    let first_ids: Vec<_> = first
        .events()
        .into_iter()
        .filter_map(|event| match event {
            Event::CapMinted { cap, .. } => Some(cap),
            _ => None,
        })
        .collect();
    let second_ids: Vec<_> = second
        .events()
        .into_iter()
        .filter_map(|event| match event {
            Event::CapMinted { cap, .. } => Some(cap),
            _ => None,
        })
        .collect();
    assert!(first_ids.contains(&first_cap.id()));
    assert!(second_ids.contains(&second_cap.id()));
    assert!(
        first_ids.iter().all(|id| !second_ids.contains(id)),
        "tenant event logs overlap: {first_ids:?} vs {second_ids:?}"
    );
}

#[test]
fn revocation_is_scoped_to_the_agent_that_holds_the_capability() {
    let (first, first_cap, first_lane) = tenant(0x77);
    let (second, second_cap, second_lane) = tenant(0x88);
    first.revoke(&first_cap);
    let error = call_text(&first, first_lane, &first_cap, "revoked")
        .expect_err("revoked capability must be refused");
    assert!(matches!(error, Error::Revoked(_)) || error.code() == "rpc/revoked");
    // The other tenant's capability was minted from a different secret and is
    // unaffected by the first tenant's revocation.
    assert_eq!(
        call_text(&second, second_lane, &second_cap, "alive").expect("other tenant"),
        Value::Text("alive".to_string())
    );
}
