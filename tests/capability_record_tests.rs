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

/// A durable capability bound to `durable-owner`: a record must name the
/// peer it was issued to, so an unbound one cannot be exported at all.
fn durable_agent() -> (Agent, active_rpc::ProviderId, active_rpc::CapHandle) {
    let agent = Agent::with_secret([0x71; 32]);
    agent.set_durable_capabilities(true);
    agent.set_record_seal_key([0x91; 32]);
    let provider = agent.register(Box::new(Echo));
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let owner = admitted(b"durable-owner");
    let cap = agent
        .mint_bound(&owner, provider, 0, attrs)
        .expect("durable cap");
    (agent, provider, cap)
}

#[test]
fn export_and_restore_are_on_the_trace() {
    // R-06: an export spends a grant and a restore mints authority from a
    // sealed record. Both are events of their own, so an operator reading the
    // tape can tell where a capability came from.
    let (agent, _provider, cap) = durable_agent();
    let record = agent.export_capability(&cap).expect("export");
    let original = cap.id();
    // One live capability per credential: release the source handle before the
    // restore, exactly as the round-trip test does.
    drop(cap);
    let owner = admitted(b"durable-owner");
    let restored = agent.restore_capability(&record, &owner).expect("restore");

    let trace = agent.trace();
    let names: Vec<&str> = trace.iter().map(|event| event.event()).collect();
    let exported = names
        .iter()
        .position(|name| *name == "cap.exported")
        .expect("the export is on the tape");
    let minted = names
        .iter()
        .position(|name| *name == "cap.minted")
        .expect("the restore mints");
    assert!(
        names[minted + 1..].contains(&"cap.restored"),
        "the restore is on the tape: {names:?}"
    );
    // The restored capability's correlation id travels with both events, and
    // the raw ids never do.
    let json = agent.trace_json();
    assert!(json.contains("\"event\":\"cap.exported\""));
    assert!(json.contains("\"event\":\"cap.restored\""));
    assert!(!json.contains(&restored.id().hex()));
    assert!(!json.contains(&original.hex()));
    assert_eq!(trace[exported].event(), "cap.exported");
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
    // The source handle is released first: one live capability per credential,
    // so a record is not a way to mint a second copy of a live grant.
    let original = cap.id();
    drop(cap);
    let owner = admitted(b"durable-owner");
    let restored = agent.restore_capability(&parsed, &owner).expect("restore");
    assert_ne!(
        restored.id(),
        original,
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
    agent.set_record_seal_key([0x92; 32]);
    agent.set_latency(100);
    let provider = agent.register(Box::new(Echo));
    let mut attrs = CapAttrs::new(&["echo"]).with_ttl_ms(100);
    attrs.persistence = CapPersistence::Durable;
    let owner = admitted(b"durable-owner");
    let cap = agent.mint_bound(&owner, provider, 0, attrs).expect("cap");
    let record = agent.export_capability(&cap).expect("export before expiry");
    drop(cap);
    // Advance the clock past the deadline through another capability.
    let other = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("clock cap");
    let lane = agent.create_lane("clock", Budget::default()).expect("lane");
    let promise = agent
        .call(lane, &other, "echo", Vec::new())
        .expect("advance");
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
    agent.set_record_seal_key([0x93; 32]);
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
    // The same peer restores it, once the source handle is gone.
    let original = cap.id();
    drop(cap);
    let restored = agent
        .restore_capability(&record, &admitted(b"owner-a"))
        .expect("restore for the bound peer");
    // Restore always re-mints, even in the same kernel: a record is authority
    // metadata, not an id.
    assert_ne!(restored.id(), original);
}

#[test]
fn restore_refuses_an_unknown_provider() {
    let (agent, _provider, cap) = durable_agent();
    let mut record = agent.export_capability(&cap).expect("export");
    record.provider = "not-registered".to_string();
    // Re-seal: the point of this case is provider resolution, not the seal.
    record.seal_with(&[0x91; 32]);
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
    agent.set_record_seal_key([0x94; 32]);
    agent.set_latency(100);
    let provider = agent.register(Box::new(Echo));
    let mut attrs = CapAttrs::new(&["echo"]).with_ttl_ms(1_000);
    attrs.persistence = CapPersistence::Durable;
    let owner = admitted(b"durable-owner");
    let cap = agent.mint_bound(&owner, provider, 0, attrs).expect("cap");
    let record = agent.export_capability(&cap).expect("export");
    drop(cap);
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
    // And the record cannot be restored after that point either. The restored
    // handle is released first, so the deadline is what refuses it.
    drop(restored);
    let record_error = agent
        .restore_capability(&record, &owner)
        .expect_err("the record's deadline passed");
    assert!(matches!(record_error, Error::Persistence(_)));
}

/// A borrowed handle names a capability this kernel minted for someone else.
/// It must not attenuate (a grant laundered out of a borrow, with the owner's
/// record pinned alive) or revoke (any receiver killing the sender).
#[test]
fn a_borrowed_handle_neither_attenuates_nor_revokes() {
    let (agent, _provider, cap) = durable_agent();
    let borrowed = agent.import(cap.id());
    assert!(!borrowed.is_owning());

    let error = agent
        .attenuate(&borrowed, CapAttrs::new(&["echo"]))
        .expect_err("a borrowed handle cannot attenuate");
    assert_eq!(error.code(), "rpc/identity", "{error}");

    let error = agent
        .revoke(&borrowed)
        .expect_err("a borrowed handle cannot revoke");
    assert_eq!(error.code(), "rpc/identity", "{error}");

    // The owner can still do both.
    let child = agent
        .attenuate(&cap, CapAttrs::new(&["echo"]))
        .expect("the owner attenuates");
    agent.revoke(&child).expect("the owner revokes");
}

/// The binding is reported before the tombstone: a wrong peer learns nothing
/// about which record ids were revoked.
#[test]
fn a_tombstoned_record_reports_the_binding_first() {
    let (agent, _provider, cap) = durable_agent();
    let record = agent.export_capability(&cap).expect("export");
    agent.revoke(&cap).expect("revoke");
    let error = agent
        .restore_capability(&record, &admitted(b"someone-else"))
        .expect_err("the wrong peer cannot probe the tombstone");
    assert_eq!(error.code(), "rpc/identity", "{error}");
    let error = agent
        .restore_capability(&record, &admitted(b"durable-owner"))
        .expect_err("the owner reaches the tombstone");
    assert_eq!(error.code(), "rpc/revoked", "{error}");
}

/// An export of an expired capability says so on the tape, like every other
/// expiry path.
#[test]
fn an_expired_export_is_an_expiry_event() {
    let agent = Agent::with_secret([0x73; 32]);
    agent.set_durable_capabilities(true);
    agent.set_record_seal_key([0x93; 32]);
    let provider = agent.register(Box::new(Echo));
    let attrs = CapAttrs::new(&["echo"]).durable().with_ttl_ms(0);
    let cap = agent
        .mint_bound(&admitted(b"durable-owner"), provider, 0, attrs)
        .expect("cap");
    let error = agent
        .export_capability(&cap)
        .expect_err("an expired capability cannot be exported");
    assert_eq!(error.code(), "rpc/revoked");
    let json = agent.trace_json();
    assert!(
        json.contains("\"event\":\"cap.expired\""),
        "the export refusal is not an expiry event: {json}"
    );
}

/// An exported record pins its object: dropping the last handle must not let
/// the provider reclaim the module the record names, or a later restore would
/// mint authority over a dead object (round 32, #3).
#[test]
fn an_exported_record_keeps_its_object_alive() {
    use active_infinity::{InfinityModule, Inode};
    use active_rpc::domain::ModuleProvider;

    let mut module = InfinityModule::new();
    let root = module.push(Inode::Str("app".to_string()));
    module.set_root(Some(root));

    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let agent = Agent::with_secret([0x71; 32]);
    agent.set_durable_capabilities(true);
    agent.set_record_seal_key([0x93; 32]);
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(&["stats"]);
    attrs.persistence = CapPersistence::Durable;
    let owner = admitted(b"durable-owner");
    let cap = agent
        .mint_bound(&owner, id, object, attrs)
        .expect("durable cap");
    let record = agent.export_capability(&cap).expect("export");
    drop(cap);
    // The provider would remove the module here without the record's pin.
    let drops = agent.take_drops(id);
    assert!(
        drops.is_empty(),
        "the pinned object was reclaimed: {drops:?}"
    );

    let restored = agent.restore_capability(&record, &owner).expect("restore");
    let lane = agent
        .create_lane("restored", Budget::default())
        .expect("lane");
    let promise = agent
        .call_as(Some(owner.identity()), lane, &restored, "stats", Vec::new())
        .expect("queued");
    agent.run();
    let value = promise.value().expect("the restored capability works");
    assert!(matches!(value, Value::Map(_)), "{value:?}");
}

/// A restored capability carries the same record id, but its record is spent:
/// dropping it must not report a restorable orphan (round 33, F4).
#[test]
fn dropping_a_restored_capability_is_not_an_orphan() {
    use active_rpc::kernel::Event;

    let (agent, provider, cap) = durable_agent();
    let record = agent.export_capability(&cap).expect("export");
    drop(cap);
    let _ = agent.take_drops(provider);
    let orphans = |agent: &Agent| {
        agent
            .events()
            .iter()
            .filter(|event| matches!(event, Event::CapRecordOrphaned(_)))
            .count()
    };
    assert_eq!(orphans(&agent), 1, "the export orphan is reported");

    let restored = match agent.restore_capability(&record, &admitted(b"durable-owner")) {
        Ok(cap) => cap,
        Err(error) => panic!("restore: {error}"),
    };
    drop(restored);
    let _ = agent.take_drops(provider);
    assert_eq!(
        orphans(&agent),
        1,
        "a spent record is not a restorable orphan"
    );
}

/// A tombstoned record can never be restored, so its object pin must be
/// released by the revocation: otherwise the provider never reclaims the
/// module and one module per record is retained (round 36, L-3).
#[test]
fn a_revoked_exported_record_releases_its_object() {
    use active_infinity::{InfinityModule, Inode};
    use active_rpc::domain::ModuleProvider;

    let mut module = InfinityModule::new();
    let root = module.push(Inode::Str("app".to_string()));
    module.set_root(Some(root));
    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let agent = Agent::with_secret([0x71; 32]);
    agent.set_durable_capabilities(true);
    agent.set_record_seal_key([0x94; 32]);
    let id = agent.register(Box::new(provider));
    let mut attrs = CapAttrs::new(&["stats"]);
    attrs.persistence = CapPersistence::Durable;
    let owner = admitted(b"durable-owner");
    let cap = agent
        .mint_bound(&owner, id, object, attrs)
        .expect("durable cap");
    let _record = agent.export_capability(&cap).expect("export");
    agent.revoke(&cap).expect("revoke");
    drop(cap);
    let drops = agent.take_drops(id);
    assert!(
        !drops.is_empty(),
        "the revoked record kept its object pinned"
    );
}
