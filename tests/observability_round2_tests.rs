//! R-15 round 2: every refusal is counted once, and every counter says what it
//! counts.
//!
//! The review found that the idempotent path recorded nothing, that a refusal
//! decided at dispatch lost its dimension, and that a second `revoke` counted as
//! a second revocation.

use active_rpc::cap::CapAttrs;
use active_rpc::kernel::{Event, Provider, MAX_CAPS_PER_MESSAGE};
use active_rpc::value::{Call, Response, Value};
use active_rpc::{Agent, Arg, Budget, ProviderId};

struct Wide {
    reply: Value,
}

impl Provider for Wide {
    fn name(&self) -> &'static str {
        "wide"
    }
    fn methods(&self) -> Vec<String> {
        vec!["ping".to_string()]
    }
    fn mutating(&self, _method: &str) -> bool {
        false
    }
    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(self.reply.clone()))
    }
}

fn agent_with(reply: Value, budget: Budget) -> (Agent, ProviderId) {
    let agent = Agent::with_secret([0x5c; 32]);
    let provider = agent.register(Box::new(Wide { reply }));
    let _ = budget;
    (agent, provider)
}

fn refusals(agent: &Agent, code: &str) -> usize {
    agent
        .events()
        .iter()
        .filter(|event| matches!(event, Event::CallRefused { code: actual, .. } if actual == code))
        .count()
}

/// #1: a replay refused because the capability was revoked leaves a trace.
#[test]
fn an_idempotent_replay_refusal_is_observable() {
    let (agent, provider) = agent_with(Value::text("ok"), Budget::default());
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["ping"]))
        .expect("mint");
    let lane = agent.create_lane("idem", Budget::default()).expect("lane");

    let first = agent
        .call_idempotent(lane, &cap, "ping", Vec::new(), "key-1")
        .expect("first call");
    let _ = first.value();
    let refused_before = agent.metrics().calls_refused;
    let revocations_before = agent.metrics().revocations;

    agent.revoke(&cap).expect("revoke");
    let error = agent
        .call_idempotent(lane, &cap, "ping", Vec::new(), "key-1")
        .expect_err("a revoked capability cannot replay");
    assert_eq!(error.code(), "rpc/revoked");
    assert_eq!(
        refusals(&agent, "rpc/revoked"),
        1,
        "the replay denial is on the tape"
    );
    assert_eq!(agent.metrics().calls_refused, refused_before + 1);

    assert_eq!(
        agent.metrics().revocations,
        revocations_before + 1,
        "one revoke is one revocation"
    );

    // A key reused with different arguments is a refusal too, on a live
    // capability (a revoked one refuses for the revocation first).
    let live = agent
        .mint(provider, 0, CapAttrs::new(&["ping"]))
        .expect("mint");
    let first = agent
        .call_idempotent(
            lane,
            &live,
            "ping",
            vec![Arg::Value(Value::Int(1))],
            "key-2",
        )
        .expect("first");
    let _ = first.value();
    let error = agent
        .call_idempotent(
            lane,
            &live,
            "ping",
            vec![Arg::Value(Value::Int(2))],
            "key-2",
        )
        .expect_err("a key cannot change meaning");
    assert_eq!(error.code(), "rpc/invalid-argument");
    assert_eq!(refusals(&agent, "rpc/invalid-argument"), 1);
}

/// #2: a ceiling that binds at dispatch keeps its dimension and its counter.
#[test]
fn a_dispatch_time_ceiling_is_counted() {
    let (agent, provider) = agent_with(Value::list((0..12).map(Value::Int)), Budget::default());
    let mut attrs = CapAttrs::new(&["ping"]);
    attrs.budget.max_array_len = 4;
    attrs.budget.max_bytes = 1 << 20;
    let cap = agent.mint(provider, 0, attrs).expect("mint");
    let lane = agent
        .create_lane("egress", Budget::default())
        .expect("lane");

    let error = agent
        .call(lane, &cap, "ping", Vec::new())
        .expect("queued")
        .value()
        .expect_err("the response is past the grant");
    assert_eq!(error.code(), "rpc/budget-exceeded");

    let events = agent.events();
    let dimensions: Vec<String> = events
        .iter()
        .filter_map(|event| match event {
            Event::BudgetExhausted { dimension, .. } => Some(dimension.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        dimensions,
        vec!["array_len".to_string()],
        "the dimension survives"
    );
    assert_eq!(agent.metrics().budget_exhaustions, 1);
    assert_eq!(agent.metrics().promises_rejected, 1);
}

/// #3: revoking twice is one revocation, and the second still succeeds.
#[test]
fn revoking_twice_is_one_revocation() {
    let (agent, provider) = agent_with(Value::text("ok"), Budget::default());
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["ping"]))
        .expect("mint");
    agent.revoke(&cap).expect("first revoke");
    agent.revoke(&cap).expect("a second revoke is idempotent");
    agent.revoke(&cap).expect("and a third");
    assert_eq!(agent.metrics().revocations, 1);
    let revoked: usize = agent
        .events()
        .iter()
        .filter(|event| matches!(event, Event::CapRevoked(_)))
        .count();
    assert_eq!(revoked, 1, "one revocation record");
}

/// #4: a transfer past the per-message ceiling names its own dimension.
#[test]
fn a_refused_transfer_names_its_dimension() {
    let (agent, provider) = agent_with(Value::text("ok"), Budget::default());
    let lane = agent.create_lane("caps", Budget::default()).expect("lane");
    let channel = agent
        .create_channel("caps", active_rpc::Direction::Both)
        .expect("channel");
    let caps: Vec<_> = (0..=MAX_CAPS_PER_MESSAGE)
        .map(|_| {
            agent
                .mint(provider, 0, CapAttrs::new(&["ping"]))
                .expect("mint")
        })
        .collect();
    let error = agent
        .send(lane, channel, Value::text("x"), &caps)
        .expect_err("a transfer that large is a flood");
    assert_eq!(error.code(), "rpc/budget-exceeded");
    let events = agent.events();
    let dimensions: Vec<String> = events
        .iter()
        .filter_map(|event| match event {
            Event::BudgetExhausted { dimension, .. } => Some(dimension.clone()),
            _ => None,
        })
        .collect();
    assert!(
        dimensions
            .iter()
            .any(|dimension| dimension == "caps per message"),
        "the dimension is named: {dimensions:?}"
    );
}

/// #5: the code a rejection carries is the closed envelope class, whatever the
/// provider authored.
#[test]
fn a_promise_rejection_code_is_closed() {
    for provider_code in ["rpc/revoked", "mcp/-12", &"x".repeat(4096)] {
        let error = active_rpc::Error::Provider {
            code: provider_code.to_string(),
        };
        assert_eq!(error.code(), "rpc/provider");
        assert!(active_rpc::error::ERROR_CODES.contains(&error.code()));
        let domain = active_rpc::Error::Domain("X001");
        assert!(active_rpc::error::ERROR_CODES.contains(&domain.code()));
    }
}
