//! C-5.5 durable versus ephemeral capability policy.

use active_rpc::cap::CapAttrs;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::{Agent, CapPersistence, Provider};

struct Echo;

impl Provider for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }
    fn methods(&self) -> Vec<String> {
        vec!["echo".into()]
    }
    fn mutating(&self, _method: &str) -> bool {
        false
    }
    fn invoke(&mut self, _object: u64, call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(
            call.args
                .iter()
                .find_map(|arg| match arg {
                    Arg::Value(value) => Some(value.clone()),
                    _ => None,
                })
                .unwrap_or(Value::Null),
        ))
    }
}

#[test]
fn durable_caps_are_refused_until_policy_allows_them() {
    let agent = Agent::new();
    let provider = agent.register(Box::new(Echo));
    assert!(!agent.durable_capabilities_allowed());
    let error = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]).durable())
        .unwrap_err();
    assert_eq!(error.code(), "rpc/capability-table");

    agent.set_durable_capabilities(true);
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]).durable())
        .expect("durable");
    assert_eq!(
        agent.cap_attrs(&cap).expect("attrs").persistence,
        CapPersistence::Durable
    );
    assert_eq!(
        agent.cap_attrs(&cap).expect("attrs").persistence,
        CapPersistence::Durable
    );

    let ephemeral = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("ephemeral");
    assert_eq!(
        agent.cap_attrs(&ephemeral).expect("attrs").persistence,
        CapPersistence::Ephemeral
    );
}

#[test]
fn durable_cannot_be_promoted_by_attenuation() {
    let parent = CapAttrs::new(&["echo"]);
    let durable_child = CapAttrs::new(&["echo"]).durable();
    let error = parent
        .attenuate(durable_child)
        .expect_err("promotion must be refused");
    assert_eq!(error.code(), "rpc/attenuation-escalation");

    // A child of a durable capability may narrow its lifetime but never
    // inherits a longer one than it asked for.
    let durable_parent = CapAttrs::new(&["echo"]).durable();
    let child = durable_parent
        .attenuate(CapAttrs::new(&["echo"]))
        .expect("child");
    assert_eq!(child.persistence, CapPersistence::Ephemeral);

    let same = durable_parent
        .attenuate(CapAttrs::new(&["echo"]).durable())
        .expect("durable child");
    assert_eq!(same.persistence, CapPersistence::Durable);
}
