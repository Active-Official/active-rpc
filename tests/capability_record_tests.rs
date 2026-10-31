//! Durable capability profile (ADR-0010): export authority as a record and
//! restore it as a fresh peer-bound capability.
//!
//! The record carries no id and no secret. Restoring re-mints, so the id
//! changes; the authority, the absolute deadline and the binding are what
//! survive.

use active_rpc::cap::CapAttrs;
use active_rpc::identity::{IdentityPolicy, PeerIdentity};
use active_rpc::kernel::Provider;
use active_rpc::value::{Call, Response, Value};
use active_rpc::{Agent, Budget, CapPersistence, CapabilityRecord, Error};

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
        Ok(Response::Value(
            call.args
                .iter()
                .find_map(|arg| match arg {
                    active_rpc::value::Arg::Value(value) => Some(value.clone()),
                    _ => None,
                })
                .unwrap_or(Value::Text("ok".into())),
        ))
    }
}

fn admitted(certificate: &[u8]) -> active_rpc::AdmittedIdentity {
    let peer = PeerIdentity::from_certificate(certificate);
    IdentityPolicy::default()
        .admit(Some(&peer), true)
        .expect("admit")
}

fn peer(certificate: &[u8]) -> PeerIdentity {
    PeerIdentity::from_certificate(certificate)
}

fn durable_agent() -> (Agent, active_rpc::ProviderId, active_rpc::CapHandle) {
    let agent = Agent::with_secret([0x71; 32]);
    agent.set_durable_capabilities(true);
    let provider = agent.register(Box::new(Echo));
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let cap = agent.mint(provider, 0, attrs).expect("durable cap");
    (agent, provider, cap)
}

#[test]
fn a_durable_capability_round_trips_through_a_record() {
    let (agent, _provider, cap) = durable_agent();
    let record = agent.export_capability(&cap).expect("export");
    assert_eq!(record.provider, "echo");
    assert_eq!(record.methods.len(), 1);
    let text = record.to_json();
    let parsed = CapabilityRecord::from_json(&text).expect("parse");
    assert_eq!(parsed, record);

    // The record carries no id and no secret: only authority metadata.
    assert!(!text.contains("\"id\""));
    assert!(!text.contains("***SECRET***"));

    // Restore for an admitted peer: same authority, new id, bound to the peer.
    let owner = admitted(b"durable-owner");
    let restored = agent.restore_capability(&parsed, &owner).expect("restore");
    assert_ne!(
        restored.id(),
        cap.id(),
        "restore re-mints, it does not resurrect"
    );
    let lane = agent
        .create_lane("restore", Budget::default())
        .expect("lane");
    let promise = agent
        .call_as(
            Some(&peer(b"durable-owner")),
            lane,
            &restored,
            "echo",
            Vec::new(),
        )
        .expect("call as the bound peer");
    agent.run();
    promise.value().expect("value");
    // The restored capability is bound: another peer cannot use it.
    let error = agent
        .call_as(
            Some(&peer(b"someone-else")),
            lane,
            &restored,
            "echo",
            Vec::new(),
        )
        .expect_err("another peer");
    assert_eq!(error.code(), "rpc/identity");
}

#[test]
fn an_ephemeral_capability_cannot_be_exported() {
    let agent = Agent::with_secret([0x72; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let error = agent
        .export_capability(&cap)
        .expect_err("an ephemeral capability must not be exported");
    assert_eq!(error.code(), "rpc/persistence");
}

#[test]
fn restore_requires_the_durable_policy() {
    let (agent, _provider, cap) = durable_agent();
    let record = agent.export_capability(&cap).expect("export");
    let other = Agent::with_secret([0x73; 32]);
    other.register(Box::new(Echo));
    let error = other
        .restore_capability(&record, &admitted(b"durable-owner"))
        .expect_err("durable restore must be opt-in");
    assert_eq!(error.code(), "rpc/persistence");
}

#[test]
fn restore_refuses_a_passed_deadline() {
    let agent = Agent::with_secret([0x74; 32]);
    agent.set_durable_capabilities(true);
    agent.set_latency(100);
    let provider = agent.register(Box::new(Echo));
    let mut attrs = CapAttrs::new(&["echo"]).with_ttl_ms(100);
    attrs.persistence = CapPersistence::Durable;
    let cap = agent.mint(provider, 0, attrs).expect("cap");
    let record = agent.export_capability(&cap).expect("export before expiry");
    let lane = agent.create_lane("clock", Budget::default()).expect("lane");
    let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("advance");
    agent.run();
    let _ = promise.value();
    let error = agent
        .restore_capability(&record, &admitted(b"durable-owner"))
        .expect_err("an expired record must not restore");
    assert_eq!(error.code(), "rpc/persistence");
}

#[test]
fn restore_refuses_a_record_bound_to_another_peer() {
    let agent = Agent::with_secret([0x75; 32]);
    agent.set_durable_capabilities(true);
    let provider = agent.register(Box::new(Echo));
    let owner = admitted(b"owner-a");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let cap = agent
        .mint_bound(&owner, provider, 0, attrs)
        .expect("bound cap");
    let record = agent.export_capability(&cap).expect("export");
    assert_eq!(record.bound_to, Some(peer(b"owner-a").fingerprint()));
    let error = agent
        .restore_capability(&record, &admitted(b"owner-b"))
        .expect_err("a bound record must not move");
    assert_eq!(error.code(), "rpc/identity");
    // The same peer restores it.
    let restored = agent
        .restore_capability(&record, &admitted(b"owner-a"))
        .expect("restore for the bound peer");
    // Restore always re-mints, even in the same kernel: a record is authority
    // metadata, not an id.
    assert_ne!(restored.id(), cap.id());
}

#[test]
fn restore_refuses_an_unknown_provider() {
    let (agent, _provider, cap) = durable_agent();
    let mut record = agent.export_capability(&cap).expect("export");
    record.provider = "not-registered".to_string();
    let error = agent
        .restore_capability(&record, &admitted(b"durable-owner"))
        .expect_err("an unknown provider must not restore");
    assert_eq!(error.code(), "rpc/persistence");
}

#[test]
fn a_malformed_or_oversized_record_is_refused() {
    for text in [
        "",
        "{}",
        r#"{"format":"active-rpc/capability-record/1"}"#,
        r#"{"format":"active-rpc/capability-record/1","provider":"echo","object":0,"methods":[],"budget":{"calls":1,"bytes":1,"wall_ms":1,"nodes":1,"depth":1,"array_len":1,"value_size":1},"read_only":false,"redact":false,"path_scope":null,"topics":null,"tool_policy":null,"bound_to":null,"expires_at":null}"#,
    ] {
        let error = CapabilityRecord::from_json(text).expect_err("must be refused");
        assert_eq!(error.code(), "rpc/persistence", "{text}");
    }
    let oversized = format!(
        "{{\"format\":\"{}\",\"pad\":\"{}\"}}",
        "active-rpc/capability-record/1",
        "x".repeat(active_rpc::persistence::MAX_RECORD_BYTES)
    );
    let error = CapabilityRecord::from_json(&oversized).expect_err("oversized");
    assert_eq!(error.code(), "rpc/persistence");
}

#[test]
fn a_restored_capability_keeps_the_original_deadline() {
    let agent = Agent::with_secret([0x76; 32]);
    agent.set_durable_capabilities(true);
    agent.set_latency(100);
    let provider = agent.register(Box::new(Echo));
    let mut attrs = CapAttrs::new(&["echo"]).with_ttl_ms(1_000);
    attrs.persistence = CapPersistence::Durable;
    let cap = agent.mint(provider, 0, attrs).expect("cap");
    let record = agent.export_capability(&cap).expect("export");
    let owner = admitted(b"durable-owner");
    let restored = agent.restore_capability(&record, &owner).expect("restore");
    // The restored deadline is the original absolute one: at t=1000 it is
    // refused, exactly like the original.
    let lane = agent
        .create_lane("deadline", Budget::default())
        .expect("lane");
    for _ in 0..9 {
        let promise = agent
            .call_as(
                Some(&peer(b"durable-owner")),
                lane,
                &restored,
                "echo",
                Vec::new(),
            )
            .expect("within the deadline");
        agent.run();
        promise.value().expect("value");
    }
    let promise = agent
        .call_as(
            Some(&peer(b"durable-owner")),
            lane,
            &restored,
            "echo",
            Vec::new(),
        )
        .expect("queued before the deadline");
    agent.run();
    let error = promise
        .value()
        .expect_err("the restored deadline must hold at dispatch");
    assert_eq!(error.code(), "rpc/revoked");
    // And the record cannot be restored after that point either.
    let record_error = agent
        .restore_capability(&record, &owner)
        .expect_err("the record's deadline passed");
    assert!(matches!(record_error, Error::Persistence(_)));
}
