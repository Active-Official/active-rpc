//! TEMPORARY R-06 round-2 audit probes. Deleted after the audit.

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

/// P1: an export refused after the reservation (empty path scope) burns the
/// grant *and* consumes the record id.
#[test]
fn probe_export_refused_after_reserve_burns_the_grant() {
    let (agent, provider) = durable_agent(0x61);
    let owner = admitted(b"owner");
    let mut attrs = CapAttrs::new(&["echo"])
        .with_budget(Budget::calls(2))
        .with_path("");
    attrs.persistence = CapPersistence::Durable;
    let cap = agent
        .mint_bound(&owner, provider, 0, attrs)
        .expect("mint with empty scope");

    let refused = agent.export_capability(&cap).expect_err("empty scope refused");
    println!("P1 first export: {} ({})", refused, refused.code());

    let second = agent.export_capability(&cap).expect_err("second export");
    println!("P1 second export: {} ({})", second, second.code());

    let lane = agent.create_lane("p1", Budget::default()).expect("lane");
    match spend(&agent, lane, &cap) {
        Ok(value) => println!("P1 local call still spends: {value:?}"),
        Err(error) => println!("P1 local call refused: {} ({})", error, error.code()),
    }
}

/// P2: the consumed-record set has no ceiling and is not covered by the
/// tombstone ceiling.
#[test]
fn probe_consumed_records_grow_without_bound() {
    let (agent, provider) = durable_agent(0x62);
    let started = std::time::Instant::now();
    let mut exported = 0usize;
    for _ in 0..70_000usize {
        let cap = bound_durable(&agent, provider, 1);
        match agent.export_capability(&cap) {
            Ok(_record) => exported += 1,
            Err(error) => {
                println!("P2 refused after {exported} exports: {error}");
                break;
            }
        }
        drop(cap);
    }
    println!(
        "P2 exported {exported} records in {:?}; tombstones={}; caps still live",
        started.elapsed(),
        agent.record_tombstone_count()
    );
    assert!(
        exported <= 65_536,
        "consumed_records exceeded every documented ceiling ({exported} entries)"
    );
}

/// P3: a child attenuated after the export cannot see the reserved grant.
#[test]
fn probe_child_after_export_cannot_spend_the_reserved_grant() {
    let (agent, provider) = durable_agent(0x63);
    let parent = bound_durable(&agent, provider, 2);
    let record = agent.export_capability(&parent).expect("export");
    println!("P3 record calls = {}", record.budget.max_calls);
    let child = agent
        .attenuate(
            &parent,
            CapAttrs::new(&["echo"]).with_budget(Budget::calls(2)).durable(),
        )
        .expect("child after export");
    let lane = agent.create_lane("p3", Budget::default()).expect("lane");
    for attempt in 0..2 {
        match spend(&agent, lane, &child) {
            Ok(value) => println!("P3 child call {attempt} spent: {value:?}"),
            Err(error) => println!("P3 child call {attempt} refused: {} ({})", error, error.code()),
        }
    }
    drop(record);
}

/// P4: a failed restore must not poison `restored_records`.
#[test]
fn probe_failed_restore_does_not_poison_the_record() {
    let (source, provider) = durable_agent(0x64);
    let cap = bound_durable(&source, provider, 3);
    let mut record = source.export_capability(&cap).expect("export");
    let good: u64 = record.budget.max_calls;
    // A zero-call budget is refused by Budget::check inside mint_restored.
    record.budget.max_calls = 0;
    record.seal_with(&[0x86; 32]);
    let error = source
        .restore_capability(&record, &admitted(b"owner"))
        .expect_err("zero budget refused");
    println!("P4 zero-budget restore: {} ({})", error, error.code());
    record.budget.max_calls = good;
    record.seal_with(&[0x86; 32]);
    match source.restore_capability(&record, &admitted(b"owner")) {
        Ok(_) => println!("P4 retry after the refusal restored: ok"),
        Err(error) => println!("P4 retry after the refusal refused: {error} ({})", error.code()),
    }
}

/// P5: export/restore/export chains preserve the total grant.
#[test]
fn probe_chain_preserves_the_grant() {
    let (k1, provider) = durable_agent(0x65);
    let cap = bound_durable(&k1, provider, 3);
    let r1 = k1.export_capability(&cap).expect("export k1");
    let lane1 = k1.create_lane("k1", Budget::default()).expect("lane");
    println!("P5 k1 first record calls={}", r1.budget.max_calls);

    let (k2, _) = durable_agent(0x66);
    let c2 = k2.restore_capability(&r1, &admitted(b"owner")).expect("restore k2");
    let r2 = k2.export_capability(&c2).expect("re-export k2");
    println!(
        "P5 k2 record calls={} same id={}",
        r2.budget.max_calls,
        r2.record_id == r1.record_id
    );

    let (k3, _) = durable_agent(0x67);
    let c3 = k3.restore_capability(&r2, &admitted(b"owner")).expect("restore k3");
    let lane3 = k3.create_lane("k3", Budget::default()).expect("lane");

    let mut spent = 0;
    loop {
        match spend(&k3, lane3, &c3) {
            Ok(_) => spent += 1,
            Err(error) => {
                println!("P5 k3 stopped after {spent} calls: {error}");
                break;
            }
        }
        if spent > 10 {
            println!("P5 k3 spent more than the exported grant!");
            break;
        }
    }
    println!("P5 k3 spent {spent} calls");
    // k1 cannot spend its own grant.
    match spend(&k1, lane1, &cap) {
        Ok(_) => println!("P5 k1 still spends!"),
        Err(error) => println!("P5 k1 refused: {error} ({})", error.code()),
    }
}

/// P6: export of a tombstoned-but-live record id hands out a dead credential
/// and burns the local grant.
#[test]
fn probe_export_of_a_tombstoned_record_id() {
    let (agent, provider) = durable_agent(0x68);
    let cap = bound_durable(&agent, provider, 2);
    let first = agent.export_capability(&cap).expect("first export");
    let id = first.record_id;
    drop(first);
    // A deployment replay decides this id is dead; the local handle stays live.
    agent.tombstone_record(id).expect("tombstone");
    let lane = agent.create_lane("p6", Budget::default()).expect("lane");
    match spend(&agent, lane, &cap) {
        Ok(_) => println!("P6 local cap still spends after a tombstone"),
        Err(error) => println!("P6 local cap refused: {error} ({})", error.code()),
    }
    match agent.export_capability(&cap) {
        Ok(_) => println!("P6 re-export allowed"),
        Err(error) => println!("P6 re-export refused: {error} ({})", error.code()),
    }
    // And a fresh cap whose id was tombstoned before the export.
    let fresh = bound_durable(&agent, provider, 2);
    println!(
        "P6 fresh cap tombstones={} (no API exposes a cap's record id before export)",
        agent.record_tombstone_count()
    );
    drop(fresh);
}
