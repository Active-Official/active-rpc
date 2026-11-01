//! TEMPORARY R-06 round-2 audit probes (second batch). Deleted after the audit.

use active_rpc::cap::CapAttrs;
use active_rpc::identity::{IdentityPolicy, PeerIdentity};
use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::{Agent, Budget, CapHandle, CapPersistence};

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
                    Arg::Value(value) => Some(value.clone()),
                    _ => None,
                })
                .unwrap_or(Value::text("ok")),
        ))
    }
}

fn admitted(certificate: &[u8]) -> active_rpc::AdmittedIdentity {
    let peer = PeerIdentity::from_certificate(certificate);
    IdentityPolicy::default()
        .admit(Some(&peer), true)
        .expect("admit")
}

fn durable_agent(seed: u8) -> (Agent, active_rpc::ProviderId) {
    let agent = Agent::with_secret([seed; 32]);
    agent.set_durable_capabilities(true);
    agent.set_record_seal_key([0x86; 32]);
    let provider = agent.register(Box::new(Echo));
    (agent, provider)
}

fn bound_durable(agent: &Agent, provider: active_rpc::ProviderId, calls: u64) -> CapHandle {
    let owner = admitted(b"owner");
    let mut attrs = CapAttrs::new(&["echo"])
        .with_budget(Budget::calls(calls))
        .durable();
    attrs.persistence = CapPersistence::Durable;
    agent
        .mint_bound(&owner, provider, 0, attrs)
        .expect("durable cap")
}

fn spend(agent: &Agent, lane: active_rpc::LaneId, cap: &CapHandle) -> active_rpc::Result<Value> {
    let owner = PeerIdentity::from_certificate(b"owner");
    let promise = agent.call_as(Some(&owner), lane, cap, "echo", Vec::new())?;
    agent.run();
    promise.value()
}

/// P4b: a restore that fails inside `mint_restored` must not consume the record.
#[test]
fn probe_failed_mint_does_not_consume_the_record() {
    let (source, provider) = durable_agent(0x71);
    let cap = bound_durable(&source, provider, 3);
    let mut record = source.export_capability(&cap).expect("export");

    let (restart, _) = durable_agent(0x72);
    let good = record.budget.max_calls;
    record.budget.max_calls = 0;
    record.seal_with(&[0x86; 32]);
    let error = restart
        .restore_capability(&record, &admitted(b"owner"))
        .expect_err("zero budget refused");
    println!("P4b zero-budget restore: {} ({})", error, error.code());

    record.budget.max_calls = good;
    record.seal_with(&[0x86; 32]);
    match restart.restore_capability(&record, &admitted(b"owner")) {
        Ok(_) => println!("P4b retry restored: ok (the failed mint did not consume)"),
        Err(error) => println!("P4b retry refused: {error} ({})", error.code()),
    }
}

/// P7: a tombstone is not enforced at dispatch: a live capability restored from
/// the record keeps working after the kill switch is replayed.
#[test]
fn probe_a_tombstone_does_not_reach_a_live_capability() {
    let (source, provider) = durable_agent(0x73);
    let cap = bound_durable(&source, provider, 3);
    let record = source.export_capability(&cap).expect("export");

    let (restart, _) = durable_agent(0x74);
    let restored = restart
        .restore_capability(&record, &admitted(b"owner"))
        .expect("restore");
    let lane = restart.create_lane("p7", Budget::default()).expect("lane");

    // The operator replays the kill list after the restore path already ran.
    restart.tombstone_record(record.record_id).expect("tombstone");
    println!(
        "P7 tombstoned={} live caps still spend:",
        restart.record_is_tombstoned(&record.record_id)
    );
    for attempt in 0..4 {
        match spend(&restart, lane, &restored) {
            Ok(_) => println!("P7   call {attempt} after the tombstone: spent"),
            Err(error) => println!("P7   call {attempt}: {error} ({})", error.code()),
        }
    }
    // And the tombstoned credential can still be exported again.
    match restart.export_capability(&restored) {
        Ok(_) => println!("P7 re-export of a tombstoned credential: allowed"),
        Err(error) => println!("P7 re-export: {error} ({})", error.code()),
    }
}

/// P8: the ancestor stays bound after the parent handle is dropped.
#[test]
fn probe_dropped_parent_still_binds_the_child() {
    let (agent, provider) = durable_agent(0x75);
    let parent = bound_durable(&agent, provider, 1);
    let child = agent
        .attenuate(
            &parent,
            CapAttrs::new(&["echo"]).with_budget(Budget::calls(1)).durable(),
        )
        .expect("child");
    let lane = agent.create_lane("p8", Budget::default()).expect("lane");
    let _ = spend(&agent, lane, &child).expect("first call");
    drop(parent);
    match agent.export_capability(&child) {
        Ok(record) => println!("P8 exported calls={}", record.budget.max_calls),
        Err(error) => println!("P8 export refused: {error} ({})", error.code()),
    }
}

/// P9: two exports that share an ancestor cannot each carry the whole grant.
#[test]
fn probe_sibling_exports_share_the_ancestor() {
    let (agent, provider) = durable_agent(0x76);
    let parent = bound_durable(&agent, provider, 4);
    let first = agent
        .attenuate(
            &parent,
            CapAttrs::new(&["echo"]).with_budget(Budget::calls(4)).durable(),
        )
        .expect("first");
    let second = agent
        .attenuate(
            &parent,
            CapAttrs::new(&["echo"]).with_budget(Budget::calls(4)).durable(),
        )
        .expect("second");
    let r1 = agent.export_capability(&first).expect("export first");
    println!("P9 first record calls={}", r1.budget.max_calls);
    match agent.export_capability(&second) {
        Ok(r2) => println!("P9 second record calls={}", r2.budget.max_calls),
        Err(error) => println!("P9 second export refused: {error} ({})", error.code()),
    }
}

/// P10: the round-1 refusals still hold (spent, revoked, expired).
#[test]
fn probe_refusals_still_hold() {
    let (agent, provider) = durable_agent(0x77);
    let lane = agent.create_lane("p10", Budget::default()).expect("lane");

    let spent = bound_durable(&agent, provider, 1);
    let _ = spend(&agent, lane, &spent).expect("spend");
    println!(
        "P10 spent: {:?}",
        agent
            .export_capability(&spent)
            .map(|_| "exported")
            .map_err(|error| error.code())
    );

    let revoked = bound_durable(&agent, provider, 1);
    agent.revoke(&revoked).expect("revoke");
    println!(
        "P10 revoked: {:?}",
        agent
            .export_capability(&revoked)
            .map(|_| "exported")
            .map_err(|error| error.code())
    );

    let owner = admitted(b"owner");
    let mut attrs = CapAttrs::new(&["echo"])
        .with_budget(Budget::calls(1))
        .with_ttl_ms(10);
    attrs.persistence = CapPersistence::Durable;
    let expiring = agent.mint_bound(&owner, provider, 0, attrs).expect("ttl cap");
    for _ in 0..20 {
        let _ = spend(&agent, lane, &expiring);
        if agent.export_capability(&expiring).is_err() {
            break;
        }
    }
    println!(
        "P10 expired: {:?}",
        agent
            .export_capability(&expiring)
            .map(|_| "exported")
            .map_err(|error| error.code())
    );
}
