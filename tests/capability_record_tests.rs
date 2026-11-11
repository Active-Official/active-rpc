//! Durable capability profile (ADR-0010): export authority as a record and
//! restore it as a fresh peer-bound capability.
//!
//! The record carries no id and no secret. Restoring re-mints, so the id
//! changes; the authority, the absolute deadline and the binding are what
//! survive.

use active_infinity::{InfinityModule, Inode, SecretBytes};
use active_rpc::cap::CapAttrs;
use active_rpc::domain::ModuleProvider;
use active_rpc::identity::{IdentityPolicy, PeerIdentity};
use active_rpc::kernel::{Provider, MAX_LINEAGE_DEPTH};
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::{Agent, Budget, CapHandle, CapPersistence, CapabilityRecord, Error, LaneId};

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
    let provider = agent.register(Box::new(Echo)).expect("register provider");
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
    let restored = agent
        .restore_capability_in_process_only(&record, &owner)
        .expect("restore");

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
    let restored = agent
        .restore_capability_in_process_only(&parsed, &owner)
        .expect("restore");
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
    let provider = agent.register(Box::new(Echo)).expect("register provider");
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
    other.register(Box::new(Echo)).expect("register provider");
    let error = other
        .restore_capability_in_process_only(&record, &admitted(b"durable-owner"))
        .expect_err("durable restore must be opt-in");
    assert_eq!(error.code(), "rpc/persistence");
}

#[test]
fn restore_refuses_a_passed_deadline() {
    let agent = Agent::with_secret([0x74; 32]);
    agent.set_durable_capabilities(true);
    agent.set_record_seal_key([0x92; 32]);
    agent.set_latency(100);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
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
        .restore_capability_in_process_only(&record, &admitted(b"durable-owner"))
        .expect_err("an expired record must not restore");
    assert_eq!(error.code(), "rpc/persistence");
}

#[test]
fn restore_refuses_a_record_bound_to_another_peer() {
    let agent = Agent::with_secret([0x75; 32]);
    agent.set_durable_capabilities(true);
    agent.set_record_seal_key([0x93; 32]);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let owner = admitted(b"owner-a");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let cap = agent
        .mint_bound(&owner, provider, 0, attrs)
        .expect("bound cap");
    let record = agent.export_capability(&cap).expect("export");
    assert_eq!(record.bound_to, Some(peer(b"owner-a").fingerprint()));
    let error = agent
        .restore_capability_in_process_only(&record, &admitted(b"owner-b"))
        .expect_err("a bound record must not move");
    assert_eq!(error.code(), "rpc/identity");
    // The same peer restores it, once the source handle is gone.
    let original = cap.id();
    drop(cap);
    let restored = agent
        .restore_capability_in_process_only(&record, &admitted(b"owner-a"))
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
        .restore_capability_in_process_only(&record, &admitted(b"durable-owner"))
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
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let mut attrs = CapAttrs::new(&["echo"]).with_ttl_ms(1_000);
    attrs.persistence = CapPersistence::Durable;
    let owner = admitted(b"durable-owner");
    let cap = agent.mint_bound(&owner, provider, 0, attrs).expect("cap");
    let record = agent.export_capability(&cap).expect("export");
    drop(cap);
    let owner = admitted(b"durable-owner");
    let restored = agent
        .restore_capability_in_process_only(&record, &owner)
        .expect("restore");
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
        .restore_capability_in_process_only(&record, &owner)
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
        .restore_capability_in_process_only(&record, &admitted(b"someone-else"))
        .expect_err("the wrong peer cannot probe the tombstone");
    assert_eq!(error.code(), "rpc/identity", "{error}");
    let error = agent
        .restore_capability_in_process_only(&record, &admitted(b"durable-owner"))
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
    let provider = agent.register(Box::new(Echo)).expect("register provider");
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
    let id = agent
        .register(Box::new(provider))
        .expect("register provider");
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

    let restored = agent
        .restore_capability_in_process_only(&record, &owner)
        .expect("restore");
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

    let restored =
        match agent.restore_capability_in_process_only(&record, &admitted(b"durable-owner")) {
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
    let id = agent
        .register(Box::new(provider))
        .expect("register provider");
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

/// Tombstoning an exported record after its handle was dropped still releases
/// the export pin: the provider must reclaim the module (round 38, F3).
#[test]
fn a_tombstone_after_the_handle_is_dropped_releases_the_pin() {
    use active_infinity::{InfinityModule, Inode};
    use active_rpc::domain::ModuleProvider;

    let mut module = InfinityModule::new();
    let root = module.push(Inode::Str("app".to_string()));
    module.set_root(Some(root));
    let mut provider = ModuleProvider::new();
    let object = provider.install(module).expect("install");
    let agent = Agent::with_secret([0x71; 32]);
    agent.set_durable_capabilities(true);
    agent.set_record_seal_key([0x96; 32]);
    let id = agent
        .register(Box::new(provider))
        .expect("register provider");
    let mut attrs = CapAttrs::new(&["stats"]);
    attrs.persistence = CapPersistence::Durable;
    let owner = admitted(b"durable-owner");
    let cap = agent
        .mint_bound(&owner, id, object, attrs)
        .expect("durable cap");
    let record = agent.export_capability(&cap).expect("export");
    drop(cap);
    let _ = agent.take_drops(id);
    agent.tombstone_record(record.record_id).expect("tombstone");
    // The tombstone queues the provider drop; a run delivers it.
    agent.run();
    let drops = agent.take_drops(id);
    assert!(
        !drops.is_empty(),
        "a tombstoned record kept its object pinned"
    );
}

/// A restart with a replayed kill list mints a fresh record id instead of
/// re-issuing the tombstoned one (RPC-02).
///
/// This test used to assert the opposite — that the second kernel's first
/// durable capability re-issued serial 0 and its export was refused as
/// tombstoned (round 38, F2). The mint now skips any serial whose record id
/// the kill list holds, so the fresh grant carries a new id and exports.
/// The export-side tombstone check itself is unchanged: a capability that
/// did carry a tombstoned id is still refused there, before anything is
/// reserved.
#[test]
fn a_restart_after_a_tombstone_mints_a_fresh_record_id() {
    let (agent, _provider, cap) = durable_agent();
    let record = agent.export_capability(&cap).expect("export");
    agent.revoke(&cap).expect("revoke");
    drop(cap);
    agent.tombstone_record(record.record_id).expect("tombstone");

    // A second kernel with the same secret used to re-issue serial 0, so
    // its first durable capability carried the tombstoned record id.
    let second = Agent::with_secret([0x71; 32]);
    second.set_durable_capabilities(true);
    second.set_record_seal_key([0x91; 32]);
    // A restart replays its kill list, so the tombstone is local knowledge.
    second
        .tombstone_record(record.record_id)
        .expect("replay the tombstone");
    let provider = second.register(Box::new(Echo)).expect("register provider");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let owner = admitted(b"durable-owner");
    let cap = second
        .mint_bound(&owner, provider, 0, attrs)
        .expect("durable cap");
    let fresh = second
        .export_capability(&cap)
        .expect("the fresh grant exports");
    assert_ne!(
        fresh.record_id, record.record_id,
        "the restart must skip the tombstoned serial"
    );
    let _ = provider;
}

/// Rotating a capability's peer invalidates any exported record for the old
/// peer: the credential was bound to the identity the rotation removes
/// (round 39, M-2).
#[test]
fn a_rotation_tombstones_the_records_of_the_old_peer() {
    let (agent, _provider, cap) = durable_agent();
    let record = agent.export_capability(&cap).expect("export");
    let old = peer(b"durable-owner");
    let new = admitted(b"rotated-owner");
    agent
        .reintroduce_to(&cap, &old, &new)
        .expect("rotate the binding");
    let error = agent
        .restore_capability_in_process_only(&record, &admitted(b"durable-owner"))
        .expect_err("the old peer's record is tombstoned");
    assert_eq!(error.code(), "rpc/revoked", "{error}");
}

/// The parser refuses a record with a deadline but no lease, the shape restore
/// always refuses: it must not advertise a record it can never serve
/// (round 39, L-5).
#[test]
fn a_record_with_a_deadline_but_no_lease_is_refused_by_the_parser() {
    let agent = Agent::with_secret([0x71; 32]);
    agent.set_durable_capabilities(true);
    agent.set_record_seal_key([0x97; 32]);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    attrs.ttl_ms = Some(60_000);
    let owner = admitted(b"durable-owner");
    let cap = agent
        .mint_bound(&owner, provider, 0, attrs)
        .expect("durable cap");
    let record = agent.export_capability(&cap).expect("export");
    let mut value: serde_json::Value = serde_json::from_str(&record.to_json()).expect("json");
    value["lease_ms"] = serde_json::Value::Null;
    assert!(
        value["expires_at"].is_number(),
        "the fixture has a deadline"
    );
    let text = serde_json::to_string(&value).expect("serialize");
    let error = CapabilityRecord::from_json(&text).expect_err("no lease");
    assert_eq!(error.code(), "rpc/persistence", "{error}");
}

// ---------------------------------------------------------------------------
// Round 40
// ---------------------------------------------------------------------------

/// Spend every tombstone slot the kernel has, so the next one is refused.
fn fill_tombstones(agent: &Agent) {
    for index in 0..active_rpc::kernel::MAX_TOMBSTONES {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&(index as u64).to_be_bytes());
        id[31] = 0xA5;
        agent
            .tombstone_record(id)
            .expect("a tombstone with room remains");
    }
    assert_eq!(
        agent.record_tombstone_count(),
        active_rpc::kernel::MAX_TOMBSTONES
    );
}

/// A rotation that cannot record its tombstones must not be half applied: the
/// subtree stays bound to the peer it was bound to (round 40, R-07-1).
#[test]
fn a_refused_rotation_leaves_the_binding_alone() {
    let (agent, _provider, ancestor) = durable_agent();
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let child = agent.attenuate(&ancestor, attrs).expect("attenuate");
    let _record = agent.export_capability(&child).expect("export");

    fill_tombstones(&agent);
    let old = peer(b"durable-owner");
    let new = admitted(b"rotated-owner");
    let error = agent
        .reintroduce_to(&ancestor, &old, &new)
        .expect_err("no tombstone budget is left");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");

    // Either fully rotated or fully untouched: a refusal must report the truth.
    assert_eq!(
        agent.cap_attrs(&ancestor).expect("attrs").bound_to,
        Some(old.fingerprint())
    );
    assert_eq!(
        agent.cap_attrs(&child).expect("attrs").bound_to,
        Some(old.fingerprint())
    );
    // And the retry reports the same state rather than "already rotated".
    let _ = agent.reintroduce_to(&ancestor, &old, &new);
    assert_eq!(
        agent.cap_attrs(&ancestor).expect("attrs").bound_to,
        Some(old.fingerprint())
    );
}

/// A rotation withdraws the record of a peer even when the exporting handle is
/// gone: the documented orphan workflow leaves no capability record to match
/// (round 40, R-07-2).
#[test]
fn a_rotation_tombstones_the_record_of_a_dropped_exporter() {
    let (agent, _provider, ancestor) = durable_agent();
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let child = agent.attenuate(&ancestor, attrs).expect("attenuate");
    let record = agent.export_capability(&child).expect("export");
    drop(child);
    agent.run();

    let old = peer(b"durable-owner");
    let new = admitted(b"rotated-owner");
    agent
        .reintroduce_to(&ancestor, &old, &new)
        .expect("rotate the binding");
    let error = agent
        .restore_capability_in_process_only(&record, &admitted(b"durable-owner"))
        .expect_err("the retired peer's record is tombstoned");
    assert_eq!(error.code(), "rpc/revoked", "{error}");
    // A deployment can find the kill through its own API and append it to its
    // persistent kill list (round 41, F6).
    assert!(
        agent.record_is_tombstoned(&record.record_id),
        "the rotation's kill is visible to the deployment"
    );
}

/// A restore is a durable mint, so it obeys the tombstone budget the mint
/// obeys; without that the set grew past its ceiling (round 40, residual R-3).
#[test]
fn a_restore_is_refused_when_the_tombstone_budget_is_spent() {
    let (agent, _provider, cap) = durable_agent();
    let record = agent.export_capability(&cap).expect("export");
    drop(cap);
    agent.run();
    fill_tombstones(&agent);
    let error = agent
        .restore_capability_in_process_only(&record, &admitted(b"durable-owner"))
        .expect_err("no tombstone budget is left");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    assert_eq!(
        agent.record_tombstone_count(),
        active_rpc::kernel::MAX_TOMBSTONES,
        "a refused restore adds no tombstone"
    );
}

/// Two records can name one provider object; restoring one must not drop the
/// object the other still pins (round 40, residual R-1).
#[test]
fn two_records_on_one_object_hold_two_pins() {
    let (agent, provider, first) = durable_agent();
    let owner = admitted(b"durable-owner");
    let second = agent
        .mint_bound(&owner, provider, 0, agent.cap_attrs(&first).expect("attrs"))
        .expect("a second durable cap on the same object");
    let first_record = agent.export_capability(&first).expect("export");
    let second_record = agent.export_capability(&second).expect("export");
    drop(first);
    drop(second);
    assert!(
        agent.take_drops(provider).is_empty(),
        "both records still pin the object"
    );

    let restored = agent
        .restore_capability_in_process_only(&first_record, &owner)
        .expect("restore the first");
    assert!(
        agent.take_drops(provider).is_empty(),
        "the second record still pins the object"
    );
    drop(restored);
    assert!(
        agent.take_drops(provider).is_empty(),
        "the second record still pins the object after the restored handle drops"
    );

    let _restored = agent
        .restore_capability_in_process_only(&second_record, &owner)
        .expect("restore the second");
}

// ---------------------------------------------------------------------------
// Round 41
// ---------------------------------------------------------------------------

/// A rotation retires the records of the rotated subtree, not every record the
/// retired peer holds: a sibling capability stays usable (round 41, F2).
#[test]
fn a_rotation_leaves_a_siblings_record_restorable() {
    let (agent, provider, first) = durable_agent();
    let owner = admitted(b"durable-owner");
    let second = agent
        .mint_bound(&owner, provider, 0, agent.cap_attrs(&first).expect("attrs"))
        .expect("a second durable cap bound to the same peer");
    let first_record = agent.export_capability(&first).expect("export first");
    let second_record = agent.export_capability(&second).expect("export second");

    let old = peer(b"durable-owner");
    let new = admitted(b"rotated-owner");
    agent
        .reintroduce_to(&first, &old, &new)
        .expect("rotate the binding");
    // A record is restorable once its exporting handle is gone.
    drop(first);
    drop(second);
    agent.run();

    assert!(
        agent.record_is_tombstoned(&first_record.record_id),
        "the rotated capability's record is retired"
    );
    assert!(
        !agent.record_is_tombstoned(&second_record.record_id),
        "the sibling's record is not this rotation's authority"
    );
    let restored = agent
        .restore_capability_in_process_only(&second_record, &owner)
        .expect("the sibling record is still restorable");
    let error = agent
        .restore_capability_in_process_only(&first_record, &owner)
        .expect_err("the rotated capability's record is tombstoned");
    assert_eq!(error.code(), "rpc/revoked", "{error}");
    drop(restored);
}

/// A registry at its ceiling refuses a restore *before* the claim, so the
/// record stays usable once capacity frees (round 41, F7).
#[test]
fn a_restore_refused_by_a_full_registry_does_not_spend_the_record() {
    use active_rpc::kernel::MAX_CAPS;
    use active_rpc::persistence::MemoryRecordStore;

    let (agent, provider, cap) = durable_agent();
    let owner = admitted(b"durable-owner");
    let record = agent.export_capability(&cap).expect("export");
    drop(cap);
    agent.run();

    // Fill the capability registry and keep every handle alive: dropping one
    // would remove its record from the registry.
    let mut held = Vec::with_capacity(MAX_CAPS);
    loop {
        match agent.mint(provider, 0, CapAttrs::new(&["echo"])) {
            Ok(cap) => held.push(cap),
            Err(error) => {
                assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
                break;
            }
        }
    }
    assert_eq!(held.len(), MAX_CAPS, "the registry is full");
    let mut store = MemoryRecordStore::new();
    let error = agent
        .restore_capability_with(&record, &owner, Some(&mut store))
        .expect_err("the registry is full");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    assert!(
        store.is_empty(),
        "a deterministic refusal must not spend the claim"
    );

    held.pop();
    agent
        .restore_capability_with(&record, &owner, Some(&mut store))
        .expect("the record is still usable once capacity frees");
}

/// A record's present fields must have the type the format defines, and its
/// arrays must be canonical: two texts with one meaning shared one seal
/// (round 41, F4).
#[test]
fn a_record_with_a_coerced_field_or_an_unsorted_list_is_refused() {
    let (agent, _provider, cap) = durable_agent();
    let record = agent.export_capability(&cap).expect("export");
    let base: serde_json::Value = serde_json::from_str(&record.to_json()).expect("json");

    let mutated = |key: &str, value: serde_json::Value| {
        let mut object = base.clone();
        object[key] = value;
        serde_json::to_string(&object).expect("serialize")
    };
    for (key, value) in [
        ("wall_clock", serde_json::Value::String("true".into())),
        ("publish", serde_json::Value::String("false".into())),
    ] {
        let error = CapabilityRecord::from_json(&mutated(key, value)).expect_err(key);
        assert_eq!(error.code(), "rpc/persistence", "{key}: {error}");
    }

    for methods in [
        serde_json::json!(["stats", "echo"]),
        serde_json::json!(["echo", "echo"]),
    ] {
        let error = CapabilityRecord::from_json(&mutated("methods", methods))
            .expect_err("a non-canonical list");
        assert_eq!(error.code(), "rpc/persistence", "{error}");
    }
}

// ---------------------------------------------------------------------------
// Round 42
// ---------------------------------------------------------------------------

/// A record's nested objects are part of its format: an extra key and a
/// reordered allow-list are texts no writer produces, and both used to parse
/// under a valid seal (round 42, F1).
#[test]
fn a_record_with_a_nested_extra_or_a_reordered_allow_list_is_refused() {
    // Mint a capability with a tool policy so the record carries one.
    let owner = admitted(b"durable-owner");
    let with_policy = {
        let agent = Agent::with_secret([0x71; 32]);
        agent.set_durable_capabilities(true);
        agent.set_record_seal_key([0x91; 32]);
        let provider = agent.register(Box::new(Echo)).expect("register provider");
        let mut attrs = CapAttrs::new(&["echo"]);
        attrs.persistence = CapPersistence::Durable;
        attrs.tool_policy = Some(active_rpc::cap::ToolPolicy {
            allowed: ["echo".to_string(), "stats".to_string()]
                .into_iter()
                .collect(),
            max_arg_bytes: 64,
            allow_process: false,
        });
        let cap = agent
            .mint_bound(&owner, provider, 0, attrs)
            .expect("durable cap");
        agent.export_capability(&cap).expect("export")
    };
    let text = with_policy.to_json();
    let mut value: serde_json::Value = serde_json::from_str(&text).expect("json");
    value["tool_policy"]["allowed"] = serde_json::json!(["stats", "echo"]);
    let reordered = serde_json::to_string(&value).expect("serialize");
    let error = CapabilityRecord::from_json(&reordered).expect_err("unsorted allow-list");
    assert_eq!(error.code(), "rpc/persistence", "{error}");

    let mut value: serde_json::Value = serde_json::from_str(&text).expect("json");
    value["tool_policy"]["bogus"] = serde_json::json!(1);
    let extra = serde_json::to_string(&value).expect("serialize");
    let error = CapabilityRecord::from_json(&extra).expect_err("unknown nested key");
    assert_eq!(error.code(), "rpc/persistence", "{error}");

    let mut value: serde_json::Value = serde_json::from_str(&text).expect("json");
    value["budget"]["bogus"] = serde_json::json!(1);
    let extra = serde_json::to_string(&value).expect("serialize");
    let error = CapabilityRecord::from_json(&extra).expect_err("unknown budget key");
    assert_eq!(error.code(), "rpc/persistence", "{error}");
}

/// A rotation to the peer that already holds the binding changes nothing, so
/// it must tombstone nothing: the subtree's own records stay restorable
/// (round 42, F3).
#[test]
fn a_rotation_to_the_same_peer_tombstones_nothing() {
    let (agent, _provider, cap) = durable_agent();
    let record = agent.export_capability(&cap).expect("export");
    let owner = peer(b"durable-owner");
    let same = admitted(b"durable-owner");
    agent
        .reintroduce_to(&cap, &owner, &same)
        .expect("a no-op rotation succeeds");
    assert!(
        !agent.record_is_tombstoned(&record.record_id),
        "nothing changed, so nothing was retired"
    );
    drop(cap);
    agent.run();
    agent
        .restore_capability_in_process_only(&record, &same)
        .expect("the record is still restorable");
}

/// A restored capability carries the record id it came from: exporting it
/// again would mint a second artifact under one credential id
/// (round 42, F5).
#[test]
fn a_restored_capability_cannot_be_exported_again() {
    // The duplicate appears across kernels: the restorer never exported the
    // record, so its own `consumed` set is empty.
    let secret = [0x71; 32];
    let (source, _provider, cap) = durable_agent();
    let record = source.export_capability(&cap).expect("export");
    drop(cap);
    source.run();

    let target = Agent::with_secret(secret);
    target.set_durable_capabilities(true);
    target.set_record_seal_key([0x91; 32]);
    target.register(Box::new(Echo)).expect("register provider");
    let restored = target
        .restore_capability_in_process_only(&record, &admitted(b"durable-owner"))
        .expect("restore");
    let error = target
        .export_capability(&restored)
        .expect_err("the record id is already spent");
    assert_eq!(error.code(), "rpc/persistence", "{error}");
}

/// A deadline is absolute in the clock domain it was minted in: after a switch
/// to the virtual clock the capability is refused instead of outliving its
/// lease (round 42, F4).
#[test]
fn a_wall_clock_deadline_does_not_survive_a_switch_to_virtual() {
    let agent = Agent::with_secret([0x5b; 32]);
    agent.use_wall_clock(true);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.ttl_ms = Some(60_000);
    let cap = agent.mint(provider, 0, attrs).expect("mint");

    // The virtual clock with zero latency does not advance at all, so the
    // wall-clock deadline must not be compared with it.
    agent.use_wall_clock(false);
    agent.set_latency(0);
    let lane = agent
        .create_lane("switch", Budget::default())
        .expect("lane");
    // The refusal may come at queue time or at dispatch; both are the same
    // authority decision, and a deadline this clock cannot read is
    // `rpc/identity` on every path (R-11 round 8, F3).
    let error = match agent.call_as(None, lane, &cap, "echo", Vec::new()) {
        Err(error) => error,
        Ok(promise) => {
            agent.run();
            promise
                .value()
                .expect_err("the deadline cannot be read in this domain")
        }
    };
    assert_eq!(error.code(), "rpc/identity", "{error}");
}

// ---------------------------------------------------------------------------
// Round 43
// ---------------------------------------------------------------------------

/// A revocation reaches a record exported from a descendant whose handle was
/// dropped: the orphan workflow must not defeat the kill switch
/// (round 43, F1).
#[test]
fn a_revocation_tombstones_an_orphaned_descendant_record() {
    use active_rpc::kernel::Event;

    let (agent, _provider, parent) = durable_agent();
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let child = agent.attenuate(&parent, attrs.clone()).expect("attenuate");
    let grandchild = agent.attenuate(&child, attrs).expect("attenuate");
    // One export: an export reserves the grant on the whole chain, so a second
    // record from the same chain has nothing left to carry.
    let record = agent
        .export_capability(&grandchild)
        .expect("export grandchild");
    drop(child);
    drop(grandchild);
    agent.run();

    agent.revoke(&parent).expect("revoke the subtree");

    assert!(
        agent.record_is_tombstoned(&record.record_id),
        "the dropped exporter's record is retired with the subtree"
    );
    let error = agent
        .restore_capability_in_process_only(&record, &admitted(b"durable-owner"))
        .expect_err("the record is tombstoned");
    assert_eq!(error.code(), "rpc/revoked", "{error}");
    assert!(
        agent
            .events()
            .iter()
            .any(|event| matches!(event, Event::CapRevoked(id) if *id == parent.id())),
        "the revocation is on the tape"
    );
}

/// A reordered record text is not the text this crate writes, so it is
/// refused even though the parsed value is the same (round 43, F2).
#[test]
fn a_record_with_a_reordered_key_is_refused() {
    let (agent, _provider, cap) = durable_agent();
    let record = agent.export_capability(&cap).expect("export");
    let mut value: serde_json::Value = serde_json::from_str(&record.to_json()).expect("json");
    // Reverse the top-level key order deterministically.
    let object = value.as_object().expect("object");
    let mut reversed = serde_json::Map::new();
    for (key, item) in object.iter().rev() {
        reversed.insert(key.clone(), item.clone());
    }
    value = serde_json::Value::Object(reversed);
    let text = serde_json::to_string(&value).expect("serialize");
    let error = CapabilityRecord::from_json(&text).expect_err("reordered keys");
    assert_eq!(error.code(), "rpc/persistence", "{error}");
}

/// A no-op rotation is not reported as a rebind (round 43, F4).
#[test]
fn a_rotation_to_the_same_peer_is_not_on_the_tape() {
    use active_rpc::kernel::Event;

    let (agent, _provider, cap) = durable_agent();
    agent
        .reintroduce_to(&cap, &peer(b"durable-owner"), &admitted(b"durable-owner"))
        .expect("a no-op rotation");
    assert!(
        !agent
            .events()
            .iter()
            .any(|event| matches!(event, Event::CapRebound { .. })),
        "no authority moved, so the tape says nothing moved"
    );
}

/// Export obeys the clock-domain rule: a deadline minted in the wall clock
/// cannot leave from a virtual-clock kernel (round 43, F5).
#[test]
fn an_export_after_a_clock_switch_is_refused() {
    let agent = Agent::with_secret([0x71; 32]);
    agent.set_durable_capabilities(true);
    agent.set_record_seal_key([0x91; 32]);
    agent.use_wall_clock(true);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    attrs.ttl_ms = Some(60_000);
    let cap = agent
        .mint_bound(&admitted(b"durable-owner"), provider, 0, attrs)
        .expect("durable cap");
    agent.use_wall_clock(false);
    let error = agent
        .export_capability(&cap)
        .expect_err("the deadline belongs to the other clock domain");
    // A domain mismatch is a durable refusal, not a revocation: the capability
    // is neither revoked nor past its lease (round 44, F-6).
    assert_eq!(error.code(), "rpc/persistence", "{error}");
    assert!(
        !agent
            .events()
            .iter()
            .any(|event| matches!(event, active_rpc::kernel::Event::CapExpired(_))),
        "no expiry is reported for a mode switch"
    );
}

// ---------------------------------------------------------------------------
// Round 44
// ---------------------------------------------------------------------------

/// A restored copy of a descendant is part of the authority tree: revoking the
/// ancestor reaches it, and so does a capability attenuated from it
/// (round 44, F-1).
#[test]
fn a_revocation_reaches_a_restored_copy_of_a_descendant() {
    let secret = [0x71; 32];
    let (source, provider, parent) = durable_agent();
    let owner = admitted(b"durable-owner");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let child = source.attenuate(&parent, attrs).expect("attenuate");
    let record = source.export_capability(&child).expect("export");
    drop(child);
    source.run();

    // Restore on the same kernel so the record and its lineage are known.
    let restored = source
        .restore_capability_in_process_only(&record, &owner)
        .expect("restore");
    let grandchild = source
        .attenuate(&restored, CapAttrs::new(&["echo"]))
        .expect("attenuate from the restored copy");

    source.revoke(&parent).expect("revoke the tree");

    let lane = source
        .create_lane("restored", Budget::default())
        .expect("lane");
    for cap in [&restored, &grandchild] {
        let outcome = source.call_as(Some(owner.identity()), lane, cap, "echo", Vec::new());
        let error = match outcome {
            Err(error) => error,
            Ok(promise) => {
                source.run();
                promise
                    .value()
                    .expect_err("the restored copy is revoked with its tree")
            }
        };
        assert_eq!(error.code(), "rpc/revoked", "{error}");
    }
    let _ = (secret, provider);
}

/// A rotation moves the restored copy too: the peer it was bound to cannot use
/// it afterwards, and the successor can (round 44, F-1).
#[test]
fn a_rotation_reaches_a_restored_copy() {
    let (agent, _provider, parent) = durable_agent();
    let owner = admitted(b"durable-owner");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let child = agent.attenuate(&parent, attrs).expect("attenuate");
    let record = agent.export_capability(&child).expect("export");
    drop(child);
    agent.run();
    let restored = agent
        .restore_capability_in_process_only(&record, &owner)
        .expect("restore");

    let old = peer(b"durable-owner");
    let new = admitted(b"rotated-owner");
    agent
        .reintroduce_to(&parent, &old, &new)
        .expect("rotate the binding");

    let lane = agent
        .create_lane("rotated", Budget::default())
        .expect("lane");
    // The successor may use the grant: the rotation moved the authority, it did
    // not delete it.
    let promise = agent
        .call_as(Some(new.identity()), lane, &restored, "echo", Vec::new())
        .expect("the successor's call is queued");
    agent.run();
    promise
        .value()
        .expect("the successor uses the restored grant");
    // The retired peer may not.
    if let Ok(promise) = agent.call_as(Some(owner.identity()), lane, &restored, "echo", Vec::new())
    {
        agent.run();
        assert!(
            promise.value().is_err(),
            "the retired peer's restored copy must not answer"
        );
    }
}

/// Introducing a capability to the peer that already holds it is not a second
/// introduction (round 44, F-5).
#[test]
fn a_repeated_introduction_is_not_a_second_introduction() {
    use active_rpc::kernel::Event;

    let (agent, provider, _bound) = durable_agent();
    let owner = admitted(b"durable-owner");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let cap = agent
        .mint(provider, 0, attrs)
        .expect("an unbound durable cap");
    agent.introduce_to(&cap, &owner).expect("introduce");
    agent.introduce_to(&cap, &owner).expect("introduce again");
    let count = agent
        .events()
        .iter()
        .filter(|event| matches!(event, Event::CapIntroduced { .. }))
        .count();
    assert_eq!(count, 1, "one introduction is one event");
}

/// The record's text has one key order, and a golden list pins it: the parser
/// compares its input with this rendering, so a dependency that changed
/// `serde_json`'s ordering would rewrite every record at rest
/// (round 44, F-3).
#[test]
fn a_record_text_has_a_fixed_key_order() {
    let (agent, _provider, cap) = durable_agent();
    let record = agent.export_capability(&cap).expect("export");
    let text = record.to_json();
    let parsed: serde_json::Value = serde_json::from_str(&text).expect("json");
    let keys: Vec<&str> = parsed
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "format",
            "provider",
            "object",
            "methods",
            "budget",
            "read_only",
            "redact",
            "path_scope",
            "topics",
            "publish",
            "tool_policy",
            "bound_to",
            "expires_at",
            "wall_clock",
            "lease_ms",
            "record_id",
            "seal",
        ],
        "the writer's key order is part of the format"
    );
    // And the golden text parses back to itself.
    assert_eq!(
        CapabilityRecord::from_json(&text)
            .expect("canonical text")
            .to_json(),
        text
    );
}

// ---------------------------------------------------------------------------
// Round 45
// ---------------------------------------------------------------------------

/// The restored copy is a real tree edge: dropping it unlinks from its
/// ancestors, so a later revoke does not report a capability that is already
/// gone (round 45, F-3).
#[test]
fn dropping_a_restored_copy_does_not_leave_a_stale_child() {
    use active_rpc::kernel::Event;

    let (agent, _provider, parent) = durable_agent();
    let owner = admitted(b"durable-owner");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let child = agent.attenuate(&parent, attrs).expect("attenuate");
    let record = agent.export_capability(&child).expect("export");
    drop(child);
    agent.run();
    let restored = agent
        .restore_capability_in_process_only(&record, &owner)
        .expect("restore");
    let restored_id = restored.id();
    drop(restored);
    agent.run();
    assert!(
        agent
            .events()
            .iter()
            .any(|event| matches!(event, Event::CapDropped(id) if *id == restored_id)),
        "the copy was dropped"
    );

    let before = agent
        .events()
        .iter()
        .filter(|event| matches!(event, Event::CapRevoked(id) if *id == restored_id))
        .count();
    agent.revoke(&parent).expect("revoke the tree");
    let after = agent
        .events()
        .iter()
        .filter(|event| matches!(event, Event::CapRevoked(id) if *id == restored_id))
        .count();
    assert_eq!(before, after, "a dropped capability is not revoked again");
}

/// A live restored copy keeps its ancestor's record (and meter) alive
/// (round 45, F-3).
#[test]
fn a_live_restored_copy_keeps_its_ancestor_alive() {
    use active_rpc::kernel::Event;

    let (agent, _provider, parent) = durable_agent();
    let owner = admitted(b"durable-owner");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let child = agent.attenuate(&parent, attrs).expect("attenuate");
    let record = agent.export_capability(&child).expect("export");
    drop(child);
    agent.run();
    let restored = agent
        .restore_capability_in_process_only(&record, &owner)
        .expect("restore");

    let parent_id = parent.id();
    drop(parent);
    agent.run();
    assert!(
        !agent
            .events()
            .iter()
            .any(|event| matches!(event, Event::CapDropped(id) if *id == parent_id)),
        "the ancestor stays while its restored copy can call"
    );
    // And the copy still works while the ancestor's handle is gone.
    let lane = agent
        .create_lane("restored-tree", Budget::default())
        .expect("lane");
    let promise = agent
        .call_as(Some(owner.identity()), lane, &restored, "echo", Vec::new())
        .expect("queued");
    agent.run();
    promise.value().expect("the restored copy answers");
    drop(restored);
}

/// The chain-depth refusal is settled before the store claim, and the export
/// already refuses to mint a record this kernel could never restore, so a
/// deterministic refusal never spends the credential (round 45, F-2; round 47,
/// F1-F2).
#[test]
fn a_chain_too_deep_to_restore_is_refused_at_export() {
    use active_rpc::kernel::MAX_LINEAGE_DEPTH;
    use active_rpc::persistence::MemoryRecordStore;

    let (agent, _provider, first) = durable_agent();
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let mut deep = first;
    for _ in 1..MAX_LINEAGE_DEPTH {
        deep = agent
            .attenuate(&deep, attrs.clone())
            .expect("one more link");
    }
    let before = agent.consumed_record_count();
    let error = agent
        .export_capability(&deep)
        .expect_err("the export cannot produce a restorable record");
    assert_eq!(error.code(), "rpc/attenuation-escalation", "{error}");
    assert_eq!(
        agent.consumed_record_count(),
        before,
        "a deterministic refusal must not spend the credential"
    );
    // No record is produced, so no store is consulted; a restore of the
    // (absent) credential cannot spend anything either.
    let store = MemoryRecordStore::new();
    assert!(store.is_empty());
}
/// Revoking a wide tree is linear: the record-id expansion is one registry
/// index, not a scan per reached capability (round 45, F-1).
#[test]
fn a_wide_revocation_is_linear() {
    let (agent, _provider, root) = durable_agent();
    let mut children = Vec::with_capacity(16_000);
    for _ in 0..16_000 {
        children.push(
            agent
                .attenuate(&root, CapAttrs::new(&["echo"]))
                .expect("one child"),
        );
    }
    let started = std::time::Instant::now();
    agent.revoke(&root).expect("revoke the tree");
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(3),
        "revoking 16 000 capabilities took {elapsed:?}"
    );
    drop(children);
}

// ---------------------------------------------------------------------------
// Round 46
// ---------------------------------------------------------------------------

/// The rotation selector uses the same ancestry: a retired peer's record behind
/// a restored copy is tombstoned (round 46, F-1).
#[test]
fn a_rotation_reaches_a_record_behind_a_restored_copy() {
    let (agent, _provider, root) = durable_agent();
    let owner = admitted(b"durable-owner");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let parent = agent.attenuate(&root, attrs.clone()).expect("attenuate");
    let source = agent.export_capability(&parent).expect("export");
    drop(parent);
    agent.run();
    let restored = agent
        .restore_capability_in_process_only(&source, &owner)
        .expect("restore");
    let child = agent.attenuate(&restored, attrs).expect("child");
    let record = agent.export_capability(&child).expect("export the child");
    drop(child);
    drop(restored);
    agent.run();

    let next = admitted(b"rotated-owner");
    agent
        .reintroduce_to(&root, &peer(b"durable-owner"), &next)
        .expect("rotate");
    assert!(
        agent.record_is_tombstoned(&record.record_id),
        "the retired peer's record stands under the rotated root"
    );
}

/// A record exported from a descendant of a restored capability carries the
/// whole tree: the restore's ancestors are tree edges, and the pin of a later
/// export must name them or a revocation of the original root misses the
/// record (round 46, F-1).
#[test]
fn a_record_exported_through_a_restored_copy_is_revoked_with_the_root() {
    let (agent, _provider, root) = durable_agent();
    let owner = admitted(b"durable-owner");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;

    // root -> child -> export -> restore (the restored copy is a tree child of
    // root with an empty budget lineage) -> descendant -> export.
    let child = agent.attenuate(&root, attrs.clone()).expect("attenuate");
    let first = agent.export_capability(&child).expect("export the child");
    drop(child);
    agent.run();
    let restored = agent
        .restore_capability_in_process_only(&first, &owner)
        .expect("restore");
    let descendant = agent.attenuate(&restored, attrs).expect("attenuate");
    let second = agent
        .export_capability(&descendant)
        .expect("export the descendant");
    drop(descendant);
    drop(restored);
    agent.run();

    agent.revoke(&root).expect("revoke the root");

    assert!(
        agent.record_is_tombstoned(&second.record_id),
        "the record of the restored subtree is retired with the root"
    );
    let error = agent
        .restore_capability_in_process_only(&second, &owner)
        .expect_err("the record is tombstoned");
    assert_eq!(error.code(), "rpc/revoked", "{error}");
}

/// The restore lineage is the pin plus the exported capability itself, so a
/// pin of `MAX - 1` already reaches the ceiling. An export there would mint a
/// credential this kernel refuses to restore after spending the grant, so it is
/// refused before the reserve and the record id stays unspent (round 47, F1-F2).
#[test]
fn an_export_past_the_restore_ceiling_is_refused_and_spends_nothing() {
    let (agent, _provider, root) = durable_agent();
    let owner = admitted(b"durable-owner");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;

    // The boundary itself: MAX - 1 links export a record this kernel would
    // refuse to restore, so the export refuses first.
    let mut too_deep = agent
        .attenuate(&root, attrs.clone())
        .expect("a fresh chain");
    for _ in 2..MAX_LINEAGE_DEPTH {
        too_deep = agent.attenuate(&too_deep, attrs.clone()).expect("link");
    }
    let before = agent.consumed_record_count();
    let error = agent
        .export_capability(&too_deep)
        .expect_err("a record that cannot be restored is not exported");
    assert_eq!(error.code(), "rpc/attenuation-escalation", "{error}");
    assert_eq!(
        agent.consumed_record_count(),
        before,
        "a refused export does not spend the record id"
    );
    let lane = agent
        .create_lane("ceiling", Budget::default())
        .expect("lane");
    agent
        .call_as(
            Some(&peer(b"durable-owner")),
            lane,
            &too_deep,
            "echo",
            Vec::new(),
        )
        .expect("the refused export leaves the grant intact");
    drop(too_deep);

    // The boundary from below: MAX - 2 links still export and restore.
    let mut deepest = root;
    for _ in 1..MAX_LINEAGE_DEPTH - 1 {
        deepest = agent.attenuate(&deepest, attrs.clone()).expect("link");
    }
    let record = agent
        .export_capability(&deepest)
        .expect("the deepest restorable chain exports");
    drop(deepest);
    agent.run();
    agent
        .restore_capability_in_process_only(&record, &owner)
        .expect("the deepest restorable chain restores");
}

/// A revocation tombstones the record, so dropping the handle afterwards is
/// not an orphan: the event promises a restorable record and an operator tool
/// keys off it (round 47, F1).
#[test]
fn a_revoked_record_is_not_an_orphan_when_the_handle_drops() {
    use active_rpc::kernel::Event;

    let (agent, provider, cap) = durable_agent();
    let record = agent.export_capability(&cap).expect("export");
    agent.revoke(&cap).expect("revoke");
    drop(cap);
    let _ = agent.take_drops(provider);
    assert!(
        agent.record_is_tombstoned(&record.record_id),
        "the revocation tombstones the credential"
    );
    let orphans = agent
        .events()
        .iter()
        .filter(|event| matches!(event, Event::CapRecordOrphaned(_)))
        .count();
    assert_eq!(orphans, 0, "a tombstoned record is not an orphan");
}

/// A narrow revoke is not O(registry): the record-id index is maintained, not
/// rebuilt per call, so N sequential leaf revokes stay linear (round 47, F3).
#[test]
fn sequential_narrow_revocations_are_linear() {
    let (agent, provider, root) = durable_agent();
    let mut children = Vec::with_capacity(20_000);
    for _ in 0..20_000 {
        children.push(
            agent
                .attenuate(&root, CapAttrs::new(&["echo"]))
                .expect("one child"),
        );
    }
    let started = std::time::Instant::now();
    for child in &children {
        agent.revoke(child).expect("one narrow revoke");
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(3),
        "revoking 20 000 leaves one by one took {elapsed:?}"
    );
    let _ = agent.take_drops(provider);
}

/// A record exported through a restored copy that has since been dropped must
/// still be reachable by the kill switch: the tombstone seeds the revoke walk
/// from the record-id index, and pruning the dropped copy's entry left the
/// descendant record restorable after `tombstone_record` claimed to kill it
/// (R-12 round 13, F1).
#[test]
fn a_tombstone_reaches_a_record_exported_through_a_dropped_restored_copy() {
    let (agent, _provider, root) = durable_agent();
    let durable = || {
        let mut attrs = CapAttrs::new(&["echo"]);
        attrs.persistence = CapPersistence::Durable;
        attrs
    };
    let child = agent.attenuate(&root, durable()).expect("child");
    let grandchild = agent.attenuate(&child, durable()).expect("grandchild");
    let parent_record = agent.export_capability(&grandchild).expect("export");
    drop(grandchild);
    let restored = agent
        .restore_capability_in_process_only(&parent_record, &admitted(b"durable-owner"))
        .expect("restore the exported record");
    let descendant = agent.attenuate(&restored, durable()).expect("descendant");
    let descendant_record = agent
        .export_capability(&descendant)
        .expect("export the descendant");
    // The documented orphan workflow drops both handles before the tombstone.
    drop(descendant);
    drop(restored);

    agent
        .tombstone_record(parent_record.record_id)
        .expect("kill switch");
    assert!(
        agent.record_is_tombstoned(&descendant_record.record_id),
        "the tombstone must reach the record exported through the dropped restored copy"
    );
    let error = agent
        .restore_capability_in_process_only(&descendant_record, &admitted(b"durable-owner"))
        .expect_err("a tombstoned descendant record is dead");
    assert_eq!(error.code(), "rpc/revoked", "{error}");
}

/// RPC-01: the record seals its ancestors' record ids.
///
/// Setup mirrors audit probe p03a: a durable root, a durable child with a
/// narrowed budget (export reserves the remaining grant on the cap and
/// every ancestor), both exported, both handles dropped, then the root's
/// record is tombstoned. The child is live nowhere, so no live-cap check
/// can see the revoked ancestor — only the sealed ancestor list can.
fn revoked_ancestor_setup() -> (Agent, active_rpc::CapabilityRecord, [u8; 32]) {
    let agent = Agent::with_secret([0x71; 32]);
    agent.set_durable_capabilities(true);
    agent.set_record_seal_key([0x91; 32]);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let owner = admitted(b"durable-owner");
    let root = agent
        .mint_bound(&owner, provider, 0, CapAttrs::new(&["echo"]).durable())
        .expect("mint root");
    let child = agent
        .attenuate(
            &root,
            CapAttrs::new(&["echo"])
                .durable()
                .with_budget(Budget::strict()),
        )
        .expect("attenuate child");
    let child_record = agent.export_capability(&child).expect("export child");
    let root_record = agent.export_capability(&root).expect("export root");
    drop(child);
    drop(root);
    (agent, child_record, root_record.record_id)
}

#[test]
fn export_seals_the_ancestors_record_ids() {
    let (agent, child_record, root_record_id) = revoked_ancestor_setup();
    assert_eq!(
        child_record.ancestor_record_ids,
        vec![root_record_id],
        "the child record must seal the root's record id"
    );
    // A first-generation capability has no ancestors to seal.
    let owner = admitted(b"durable-owner");
    let (agent2, _provider, root) = durable_agent();
    let root_record = agent2.export_capability(&root).expect("export root");
    assert!(
        root_record.ancestor_record_ids.is_empty(),
        "a root record seals an empty ancestor list"
    );
    drop(agent);
    drop(owner);
}

#[test]
fn restore_under_a_tombstoned_ancestor_is_refused() {
    let (agent, child_record, root_record_id) = revoked_ancestor_setup();
    agent
        .tombstone_record(root_record_id)
        .expect("tombstone root");
    let error = agent
        .restore_capability_in_process_only(&child_record, &admitted(b"durable-owner"))
        .expect_err("a restore under a tombstoned ancestor must fail");
    assert_eq!(error.code(), "rpc/revoked", "{error}");
}

#[test]
fn restore_under_a_live_ancestor_succeeds_and_calls() {
    let (agent, child_record, _root_record_id) = revoked_ancestor_setup();
    let owner = admitted(b"durable-owner");
    let restored = agent
        .restore_capability_in_process_only(&child_record, &owner)
        .expect("restore under a live ancestor");
    let lane = agent
        .create_lane("rpc-01-control", Budget::default())
        .expect("lane");
    let promise = agent
        .call_as(Some(owner.identity()), lane, &restored, "echo", Vec::new())
        .expect("the restored call is queued");
    agent.run();
    promise.value().expect("the restored grant answers");
}

#[test]
fn restore_under_a_tombstoned_ancestor_is_refused_cross_kernel_after_kill_list_replay() {
    let (_agent, child_record, root_record_id) = revoked_ancestor_setup();
    // A fresh kernel with the same secret and seal key never saw the
    // tombstone: the kill list reaches it the same way every kill list
    // does, replayed with `tombstone_record` before the restore (RPC-01).
    // Without the replay no kernel could know, and the restore succeeds —
    // that is the documented cross-kernel contract, not a bypass.
    let agent_b = Agent::with_secret([0x71; 32]);
    agent_b.set_durable_capabilities(true);
    agent_b.set_record_seal_key([0x91; 32]);
    agent_b.register(Box::new(Echo)).expect("register provider");
    agent_b
        .tombstone_record(root_record_id)
        .expect("replay the kill list");
    let error = agent_b
        .restore_capability_in_process_only(&child_record, &admitted(b"durable-owner"))
        .expect_err("a restore under a replayed tombstoned ancestor must fail");
    assert_eq!(error.code(), "rpc/revoked", "{error}");
}

#[test]
fn restore_without_kill_list_replay_succeeds_cross_kernel() {
    let (_agent, child_record, _root_record_id) = revoked_ancestor_setup();
    let agent_b = Agent::with_secret([0x71; 32]);
    agent_b.set_durable_capabilities(true);
    agent_b.set_record_seal_key([0x91; 32]);
    agent_b.register(Box::new(Echo)).expect("register provider");
    agent_b
        .restore_capability_in_process_only(&child_record, &admitted(b"durable-owner"))
        .expect("no replayed tombstone, so the restore succeeds");
}

#[test]
fn a_descendant_of_a_restored_capability_re_exports_its_ancestors() {
    let (agent, child_record, root_record_id) = revoked_ancestor_setup();
    let owner = admitted(b"durable-owner");
    let restored = agent
        .restore_capability_in_process_only(&child_record, &owner)
        .expect("restore under a live ancestor");
    // A restored capability itself cannot be re-exported under the same
    // record id ("the record was already exported and consumed"): the
    // documented path is to attenuate it and export the new grant.
    // The restored grant carries the narrowed strict budget the child
    // was exported with, so the attenuation must narrow, not grow, it.
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    attrs.budget = Budget::strict();
    let descendant = agent
        .attenuate(&restored, attrs)
        .expect("attenuate the restored capability");
    let re_exported = agent
        .export_capability(&descendant)
        .expect("export the descendant of the restored capability");
    assert_eq!(
        re_exported.ancestor_record_ids,
        vec![root_record_id, child_record.record_id],
        "the kill switch must survive a restore round trip: the root and \
         the restored record it came from are both ancestors"
    );
    drop(descendant);
    drop(restored);
    agent
        .tombstone_record(root_record_id)
        .expect("tombstone root");
    let error = agent
        .restore_capability_in_process_only(&re_exported, &owner)
        .expect_err("the re-exported record dies with its ancestor");
    assert_eq!(error.code(), "rpc/revoked", "{error}");
}

#[test]
fn a_legacy_record_without_an_ancestor_list_restores_under_the_old_rule() {
    // Records sealed before the ancestor field existed carry an empty
    // list and cannot prove their ancestry: they restore under the old
    // rule (own id only). This pins that limitation, so a deployment
    // that needs the guarantee knows to re-export them.
    let (agent, child_record, root_record_id) = revoked_ancestor_setup();
    let mut legacy = child_record.clone();
    legacy.ancestor_record_ids = Vec::new();
    legacy.seal_with(&[0x91; 32]);
    let parsed = active_rpc::CapabilityRecord::from_json(&legacy.to_json())
        .expect("a stripped record still parses");
    assert!(parsed.ancestor_record_ids.is_empty());
    agent
        .tombstone_record(root_record_id)
        .expect("tombstone root");
    agent
        .restore_capability_in_process_only(&parsed, &admitted(b"durable-owner"))
        .expect("a legacy record restores under the old rule");
}

/// RPC-02: a fixed-secret restart + kill-list replay never re-issues a
/// tombstoned record id, and a call queued before the replay is refused.
///
/// Mirrors audit probe `probe_sec_f1_serial_reuse_after_tombstone_replay`,
/// asserting the FIXED behaviour: the fresh mint skips the tombstoned
/// serial, so the new capability carries a new record id, calls, and
/// exports — while the tombstoned id stays dead.
#[test]
fn a_restart_with_a_replayed_kill_list_never_reissues_a_tombstoned_record_id() {
    let secret = [0x42u8; 32];
    let seal_key = [0x43u8; 32];
    let tombstoned: [u8; 32];
    {
        let agent = Agent::with_secret(secret);
        agent.set_record_seal_key(seal_key);
        agent.set_durable_capabilities(true);
        let provider = agent.register(Box::new(Echo)).expect("register provider");
        let owner = admitted(b"owner-public-certificate-bytes");
        let mut attrs = CapAttrs::new(&["echo"]);
        attrs.persistence = CapPersistence::Durable;
        let cap = agent
            .mint_bound(&owner, provider, 0, attrs)
            .expect("durable cap");
        let record = agent.export_capability(&cap).expect("export");
        tombstoned = record.record_id;
        agent
            .tombstone_record(tombstoned)
            .expect("tombstone the record");
    }
    // Restart: same secret, same seal key, kill list replayed first.
    let agent = Agent::with_secret(secret);
    agent.set_record_seal_key(seal_key);
    agent.set_durable_capabilities(true);
    agent
        .tombstone_record(tombstoned)
        .expect("replay the kill list");
    assert!(agent.record_is_tombstoned(&tombstoned));
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let owner = admitted(b"owner-public-certificate-bytes");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let cap = agent
        .mint_bound(&owner, provider, 0, attrs)
        .expect("re-mint after replay");
    // The fresh grant is a NEW credential, not the tombstoned one: it
    // calls, and its record id differs from the tombstoned one. The call
    // runs before the export because an export reserves the grant's
    // remaining calls on the capability, leaving it nothing to call with.
    let lane = agent
        .create_lane("rpc-02", Budget::default())
        .expect("lane");
    let peer = peer(b"owner-public-certificate-bytes");
    let promise = agent
        .call_as(Some(&peer), lane, &cap, "echo", Vec::new())
        .expect("queued");
    agent.run();
    promise.value().expect("the fresh grant answers");
    let record = agent.export_capability(&cap).expect("export the new cap");
    assert_ne!(
        record.record_id, tombstoned,
        "the re-mint must skip the tombstoned serial"
    );
}

/// RPC-02 (dispatch gate): a call queued before the kill list is replayed
/// is refused at dispatch, so the outcome does not depend on the order of
/// the replay and the mint. The refusal travels through the tombstone
/// revoke in practice; the dispatch-side tombstone arm is the second gate
/// for any copy that revoke cannot see.
#[test]
fn a_call_queued_before_the_kill_list_replay_is_refused_at_dispatch() {
    let (agent, _provider, cap) = durable_agent();
    let owner = admitted(b"durable-owner");
    let lane = agent
        .create_lane("rpc-02-dispatch", Budget::default())
        .expect("lane");
    let promise = agent
        .call_as(Some(owner.identity()), lane, &cap, "echo", Vec::new())
        .expect("queued");
    // The handle stays alive until dispatch: dropping the last handle
    // removes the capability from the registry, and the queued call would
    // then fail as unknown-capability instead of revoked.
    let record = agent.export_capability(&cap).expect("export");
    agent
        .tombstone_record(record.record_id)
        .expect("replay the kill list after queueing");
    agent.run();
    let error = promise.value().expect_err("the queued call must not run");
    assert_eq!(error.code(), "rpc/revoked", "{error}");
}

/// RPC-02 (attenuate arm): a child minted after a kill-list replay skips
/// a tombstoned (serial, parent) pair just like a first-generation mint.
#[test]
fn an_attenuated_child_after_a_replayed_kill_list_skips_a_tombstoned_serial() {
    let secret = [0x42u8; 32];
    let seal_key = [0x43u8; 32];
    // Tombstone the (serial 0, no parent) record id on a first kernel.
    let tombstoned: [u8; 32];
    {
        let agent = Agent::with_secret(secret);
        agent.set_record_seal_key(seal_key);
        agent.set_durable_capabilities(true);
        let provider = agent.register(Box::new(Echo)).expect("register provider");
        let owner = admitted(b"owner-public-certificate-bytes");
        let mut attrs = CapAttrs::new(&["echo"]);
        attrs.persistence = CapPersistence::Durable;
        let cap = agent
            .mint_bound(&owner, provider, 0, attrs)
            .expect("durable cap");
        let record = agent.export_capability(&cap).expect("export");
        tombstoned = record.record_id;
    }
    let agent = Agent::with_secret(secret);
    agent.set_record_seal_key(seal_key);
    agent.set_durable_capabilities(true);
    agent
        .tombstone_record(tombstoned)
        .expect("replay the kill list");
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let owner = admitted(b"owner-public-certificate-bytes");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let root = agent
        .mint_bound(&owner, provider, 0, attrs)
        .expect("root after replay");
    // The child narrows its budget: an export reserves the grant on the
    // capability and every ancestor, so a child exported at the parent's
    // full budget would leave the parent with nothing left to export.
    let mut child_attrs = CapAttrs::new(&["echo"]);
    child_attrs.persistence = CapPersistence::Durable;
    child_attrs.budget = Budget::strict();
    let child = agent
        .attenuate(&root, child_attrs)
        .expect("child after replay");
    let child_record = agent.export_capability(&child).expect("export child");
    assert_ne!(
        child_record.record_id, tombstoned,
        "the child must not reuse the tombstoned record id"
    );
    let root_record = agent.export_capability(&root).expect("export root");
    assert_ne!(
        root_record.record_id, tombstoned,
        "the root must not reuse the tombstoned record id"
    );
}

// ---------------------------------------------------------------------------
// R2-BND-03: a durable module capability is bound to its module's content
// address, so a restore cannot rebind by bare object id.
// ---------------------------------------------------------------------------

/// A plain module whose root table holds one string value (for evaluate).
fn plain_module(value: &str) -> InfinityModule {
    let mut module = InfinityModule::new();
    let node = module.push(Inode::Str(value.to_string()));
    let root = module.push(Inode::Table {
        fields: vec![("v".to_string(), node)],
    });
    module.set_root(Some(root));
    module
}

/// A module whose root table holds one structural secret.
fn secret_module(secret: &str) -> InfinityModule {
    let mut module = InfinityModule::new();
    let secret_node = module.push(Inode::Secret(SecretBytes::new(secret)));
    let root = module.push(Inode::Table {
        fields: vec![("token".to_string(), secret_node)],
    });
    module.set_root(Some(root));
    module
}

/// A durable-capable agent with the deployment's secret and seal key, and the
/// owner the records are bound to. Two agents built this way are the same
/// deployment, as in the W15 probes.
fn module_agent() -> (Agent, active_rpc::AdmittedIdentity) {
    let agent = Agent::with_secret([0x71; 32]);
    agent.set_durable_capabilities(true);
    agent.set_record_seal_key([0x91; 32]);
    (agent, admitted(b"durable-owner"))
}

fn mint_module_cap(
    agent: &Agent,
    provider: active_rpc::ProviderId,
    object: u64,
    owner: &active_rpc::AdmittedIdentity,
    methods: &[&str],
    durable: bool,
) -> CapHandle {
    let mut attrs = CapAttrs::new(methods);
    if durable {
        attrs.persistence = CapPersistence::Durable;
    }
    agent
        .mint_bound(owner, provider, object, attrs)
        .expect("module cap")
}

/// Call a method as the owner peer and return the value.
fn call_as_owner(
    agent: &Agent,
    lane: LaneId,
    cap: &CapHandle,
    method: &str,
    args: Vec<Arg>,
) -> active_rpc::Result<Value> {
    let promise = agent.call_as(Some(&peer(b"durable-owner")), lane, cap, method, args)?;
    agent.run();
    promise.value()
}

/// The domain `content_hash` answer for a module capability, without the
/// `blake3:` prefix.
fn content_hash_via(agent: &Agent, lane: LaneId, cap: &CapHandle) -> String {
    match call_as_owner(agent, lane, cap, "content_hash", Vec::new()).expect("content_hash") {
        Value::Text(text) => text.strip_prefix("blake3:").expect("prefix").to_string(),
        other => panic!("unexpected content_hash reply {other:?}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// R2-BND-03: a record exported for module A restores onto a kernel that
/// installed module B at the same object id — the restore is refused, not
/// rebound.
#[test]
fn a_restore_refuses_a_module_cap_bound_for_a_different_module() {
    let (agent_a, owner) = module_agent();
    let mut provider_a = ModuleProvider::new();
    let object_a = provider_a
        .install(plain_module("module-A"))
        .expect("install A");
    assert_eq!(object_a, 0);
    let id_a = agent_a
        .register(Box::new(provider_a))
        .expect("register provider");
    let cap_a = mint_module_cap(&agent_a, id_a, object_a, &owner, &["evaluate"], true);
    let record = agent_a.export_capability(&cap_a).expect("export");
    assert!(
        record.content_hash.is_some(),
        "a module export seals the content address"
    );
    drop(cap_a);

    let (agent_b, _) = module_agent();
    let mut provider_b = ModuleProvider::new();
    let object_b = provider_b
        .install(plain_module("module-B"))
        .expect("install B");
    assert_eq!(object_b, 0);
    let _id_b = agent_b
        .register(Box::new(provider_b))
        .expect("register provider");
    let error = agent_b
        .restore_capability_in_process_only(&record, &owner)
        .expect_err("a different module at the same id is a rebind, not a restore");
    assert_eq!(error.code(), "rpc/persistence");
    assert!(
        error.to_string().contains("does not match"),
        "the refusal names the mismatch: {error}"
    );
}

/// R2-BND-03: a record exported for module A restores onto a kernel whose
/// module provider holds nothing — the restore is refused at the restore,
/// not at the first call.
#[test]
fn a_restore_refuses_a_module_cap_when_the_object_does_not_exist() {
    let (agent_a, owner) = module_agent();
    let mut provider_a = ModuleProvider::new();
    let object_a = provider_a
        .install(plain_module("module-A"))
        .expect("install A");
    let id_a = agent_a
        .register(Box::new(provider_a))
        .expect("register provider");
    let cap_a = mint_module_cap(&agent_a, id_a, object_a, &owner, &["evaluate"], true);
    let record = agent_a.export_capability(&cap_a).expect("export");
    drop(cap_a);

    let (agent_c, _) = module_agent();
    let _id_c = agent_c
        .register(Box::new(ModuleProvider::new()))
        .expect("register provider");
    let error = agent_c
        .restore_capability_in_process_only(&record, &owner)
        .expect_err("no module lives at the object on this kernel");
    assert_eq!(error.code(), "rpc/persistence");
    assert!(
        error.to_string().contains("not installed"),
        "the refusal names the missing module: {error}"
    );
}

/// R2-BND-03: the same module on another kernel restores, and evaluates to
/// the module it was minted for.
#[test]
fn a_restore_succeeds_for_the_same_module_on_another_kernel() {
    let (agent_a, owner) = module_agent();
    let mut provider_a = ModuleProvider::new();
    let object_a = provider_a
        .install(plain_module("module-A"))
        .expect("install A");
    let id_a = agent_a
        .register(Box::new(provider_a))
        .expect("register provider");
    let cap_a = mint_module_cap(&agent_a, id_a, object_a, &owner, &["evaluate"], true);
    let record = agent_a.export_capability(&cap_a).expect("export");
    drop(cap_a);

    let (agent_b, _) = module_agent();
    let mut provider_b = ModuleProvider::new();
    let object_b = provider_b
        .install(plain_module("module-A"))
        .expect("install A");
    assert_eq!(object_b, 0);
    let _id_b = agent_b
        .register(Box::new(provider_b))
        .expect("register provider");
    let lane_b = agent_b.create_lane("b", Budget::default()).expect("lane");
    let restored = agent_b
        .restore_capability_in_process_only(&record, &owner)
        .expect("the same module restores");
    let value = call_as_owner(&agent_b, lane_b, &restored, "evaluate", vec![]).expect("evaluate");
    assert_eq!(
        value,
        Value::Map(
            [("v".to_string(), Value::Text("module-A".to_string()))]
                .into_iter()
                .collect()
        ),
        "the restored cap serves the module it was minted for"
    );
}

/// R2-BND-03 (design step 5): a record exported before a patch must not
/// silently rebind to the patched module. The sealed address is the hash at
/// export, and the patch changes it.
#[test]
fn a_restore_refuses_a_record_exported_before_a_patch() {
    let (agent, owner) = module_agent();
    let mut provider = ModuleProvider::new();
    let object = provider
        .install(plain_module("module-A"))
        .expect("install A");
    let id = agent
        .register(Box::new(provider))
        .expect("register provider");
    let cap = mint_module_cap(
        &agent,
        id,
        object,
        &owner,
        &["evaluate", "content_hash"],
        true,
    );
    let patcher = mint_module_cap(
        &agent,
        id,
        object,
        &owner,
        &["evaluate", "patch", "content_hash"],
        false,
    );
    let lane = agent.create_lane("patch", Budget::default()).expect("lane");
    let record = agent.export_capability(&cap).expect("export");
    let sealed = record
        .content_hash
        .expect("a module export seals the address");
    assert_eq!(
        content_hash_via(&agent, lane, &patcher),
        hex(&sealed),
        "the sealed address is the domain content_hash at export"
    );

    call_as_owner(
        &agent,
        lane,
        &patcher,
        "patch",
        vec![
            Arg::Value(Value::path("v")),
            Arg::Value(Value::Text("module-A-patched".to_string())),
        ],
    )
    .expect("patch");
    assert_ne!(
        content_hash_via(&agent, lane, &patcher),
        hex(&sealed),
        "the patch changes the module's address"
    );
    drop(cap);
    let error = agent
        .restore_capability_in_process_only(&record, &owner)
        .expect_err("the patched module is not the module the record was minted for");
    assert_eq!(error.code(), "rpc/persistence");
    assert!(
        error.to_string().contains("does not match"),
        "the refusal names the mismatch: {error}"
    );
}

/// R2-BND-03: the sealed address for a secret-bearing module is the redacted
/// projection's hash — never the raw hash of the secret image, or the record
/// itself would carry an offline equality oracle over the secret.
#[test]
fn a_sealed_record_carries_the_redacted_hash_for_a_secret_module() {
    let module = secret_module("s3cr3t-value");
    let bytes = active_infinity::encode(&module).expect("encode");
    let raw = active_infinity::content_hash(&bytes).expect("raw hash");
    let (agent_a, owner) = module_agent();
    let mut provider_a = ModuleProvider::new();
    let object_a = provider_a.install(module).expect("install secret module");
    let id_a = agent_a
        .register(Box::new(provider_a))
        .expect("register provider");
    let cap_a = mint_module_cap(
        &agent_a,
        id_a,
        object_a,
        &owner,
        &["evaluate", "content_hash"],
        true,
    );
    let lane_a = agent_a
        .create_lane("hash", Budget::default())
        .expect("lane");
    // Before the export: the export reserves the capability's remaining
    // grant, so a content_hash call through it afterwards would exceed its
    // budget.
    let via = content_hash_via(&agent_a, lane_a, &cap_a);
    let record = agent_a.export_capability(&cap_a).expect("export");
    let sealed = record
        .content_hash
        .expect("a module export seals the address");
    assert_eq!(
        hex(&sealed),
        via,
        "the sealed address is the domain content_hash"
    );
    assert_ne!(
        sealed, raw,
        "the sealed address is the redacted hash, not the raw hash of the secret image"
    );
    assert!(
        !record.to_json().contains(&hex(&raw)),
        "the record text must not carry the raw hash of a secret image"
    );
    drop(cap_a);

    // The same secret module on another kernel restores: the redacted
    // address is the same there.
    let (agent_b, _) = module_agent();
    let mut provider_b = ModuleProvider::new();
    let object_b = provider_b
        .install(secret_module("s3cr3t-value"))
        .expect("install same secret module");
    assert_eq!(object_b, 0);
    let _id_b = agent_b
        .register(Box::new(provider_b))
        .expect("register provider");
    agent_b
        .restore_capability_in_process_only(&record, &owner)
        .expect("the same secret module restores");
}

/// R2-BND-03: an export for a provider that serves no modules seals no hash,
/// and restores exactly as before.
#[test]
fn an_export_for_a_provider_that_serves_no_modules_seals_no_hash() {
    let (agent, _provider, cap) = durable_agent();
    let record = agent.export_capability(&cap).expect("export");
    assert_eq!(
        record.content_hash, None,
        "a non-module provider has no content address to seal"
    );
    drop(cap);
    let owner = admitted(b"durable-owner");
    agent
        .restore_capability_in_process_only(&record, &owner)
        .expect("a hash-less record for a non-module provider restores");
}

/// R2-BND-03 (migration rule): a record sealed before the hash existed
/// carries no hash. It restores when the object exists on a module provider
/// — the dead-credential half — but the hash cannot be checked, so it can
/// still rebind to a different module at the same id. That is the documented
/// migration bridge, not the fix: a deployment that needs the binding
/// re-exports the record. It refuses when the object does not exist.
#[test]
fn a_legacy_record_without_a_hash_restores_when_the_object_exists() {
    let (agent_a, owner) = module_agent();
    let mut provider_a = ModuleProvider::new();
    let object_a = provider_a
        .install(plain_module("module-A"))
        .expect("install A");
    let id_a = agent_a
        .register(Box::new(provider_a))
        .expect("register provider");
    let cap_a = mint_module_cap(&agent_a, id_a, object_a, &owner, &["evaluate"], true);
    let record = agent_a.export_capability(&cap_a).expect("export");
    assert!(record.content_hash.is_some(), "the export seals a hash");
    drop(cap_a);
    // A legacy record: the hash stripped, the seal recomputed over the
    // hash-less fields.
    let mut legacy = record.clone();
    legacy.content_hash = None;
    legacy.seal_with(&[0x91; 32]);

    // The object exists on kernel B, with a different module: the migration
    // bridge restores it (the hash cannot be checked).
    let (agent_b, _) = module_agent();
    let mut provider_b = ModuleProvider::new();
    let object_b = provider_b
        .install(plain_module("module-B"))
        .expect("install B");
    assert_eq!(object_b, 0);
    let _id_b = agent_b
        .register(Box::new(provider_b))
        .expect("register provider");
    let lane_b = agent_b.create_lane("b", Budget::default()).expect("lane");
    let restored = agent_b
        .restore_capability_in_process_only(&legacy, &owner)
        .expect("a legacy record restores when the object exists");
    let value = call_as_owner(&agent_b, lane_b, &restored, "evaluate", vec![]).expect("evaluate");
    assert_eq!(
        value,
        Value::Map(
            [("v".to_string(), Value::Text("module-B".to_string()))]
                .into_iter()
                .collect()
        ),
        "the migration bridge is the old rule: the legacy record rebinds, which is why re-export matters"
    );
}

#[test]
fn a_legacy_record_without_a_hash_refuses_when_the_object_does_not_exist() {
    let (agent_a, owner) = module_agent();
    let mut provider_a = ModuleProvider::new();
    let object_a = provider_a
        .install(plain_module("module-A"))
        .expect("install A");
    let id_a = agent_a
        .register(Box::new(provider_a))
        .expect("register provider");
    let cap_a = mint_module_cap(&agent_a, id_a, object_a, &owner, &["evaluate"], true);
    let record = agent_a.export_capability(&cap_a).expect("export");
    drop(cap_a);
    let mut legacy = record.clone();
    legacy.content_hash = None;
    legacy.seal_with(&[0x91; 32]);

    let (agent_c, _) = module_agent();
    let _id_c = agent_c
        .register(Box::new(ModuleProvider::new()))
        .expect("register provider");
    let error = agent_c
        .restore_capability_in_process_only(&legacy, &owner)
        .expect_err("a legacy record still refuses a missing object");
    assert_eq!(error.code(), "rpc/persistence");
    assert!(
        error.to_string().contains("not installed"),
        "the refusal names the missing module: {error}"
    );
}

// ---------------------------------------------------------------------------
// RPC-04 — restore without a RecordStore double-mints across kernels
// ---------------------------------------------------------------------------

/// `restore_capability` refuses without a store: the "already restored" set
/// is in-process only, so a no-store restore on a second kernel used to mint
/// a second live grant for the full recorded budget (RPC-04, SEC-F3).
#[test]
fn a_restore_without_a_store_is_refused_on_a_second_kernel() {
    use active_rpc::persistence::MemoryRecordStore;

    let (agent, _provider, cap) = durable_agent();
    let owner = admitted(b"durable-owner");
    let record = agent.export_capability(&cap).expect("export");
    drop(cap);

    // A second kernel in the same deployment: same secret, same seal key,
    // no RecordStore anywhere — the exact shape the audit probe reproduces.
    let second = Agent::with_secret([0x71; 32]);
    second.set_durable_capabilities(true);
    second.set_record_seal_key([0x91; 32]);
    second.register(Box::new(Echo)).expect("register provider");
    let error = second
        .restore_capability(&record, &owner)
        .expect_err("a no-store restore must be refused");
    assert_eq!(error.code(), "rpc/persistence", "{error}");
    assert!(
        error.to_string().contains("RecordStore"),
        "the refusal names the fix: {error}"
    );

    // The refusal burns nothing: the same record still restores through the
    // store-backed path, and the grant it mints is callable.
    let mut store = MemoryRecordStore::new();
    let restored = second
        .restore_capability_with(&record, &owner, Some(&mut store))
        .expect("the record is still usable with a store");
    let lane = second
        .create_lane("restore", Budget::default())
        .expect("lane");
    let promise = second
        .call_as(
            Some(&peer(b"durable-owner")),
            lane,
            &restored,
            "echo",
            Vec::new(),
        )
        .expect("call as the bound peer");
    second.run();
    promise.value().expect("value");
}

/// The explicit opt-in keeps the old behaviour under its own name: a
/// single-process deployment restores once per kernel, and a repeat restore
/// in the same kernel is still refused (RPC-04).
#[test]
fn an_in_process_only_restore_still_restores_once_per_kernel() {
    let (agent, _provider, cap) = durable_agent();
    let owner = admitted(b"durable-owner");
    let record = agent.export_capability(&cap).expect("export");
    drop(cap);

    let second = Agent::with_secret([0x71; 32]);
    second.set_durable_capabilities(true);
    second.set_record_seal_key([0x91; 32]);
    second.register(Box::new(Echo)).expect("register provider");
    let restored = second
        .restore_capability_in_process_only(&record, &owner)
        .expect("the explicit single-process path still restores");
    let lane = second
        .create_lane("restore", Budget::default())
        .expect("lane");
    let promise = second
        .call_as(
            Some(&peer(b"durable-owner")),
            lane,
            &restored,
            "echo",
            Vec::new(),
        )
        .expect("call as the bound peer");
    second.run();
    promise.value().expect("value");
    drop(restored);
    second.run();
    let error = second
        .restore_capability_in_process_only(&record, &owner)
        .expect_err("a repeat restore in the same kernel is refused");
    assert_eq!(error.code(), "rpc/persistence", "{error}");
}
