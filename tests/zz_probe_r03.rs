//! TEMPORARY R-03 round-3 probe harness. Removed after the audit.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::rc::Rc;

use active_rpc::cap::{CapAttrs, CapPersistence};
use active_rpc::identity::{IdentityPolicy, PeerIdentity};
use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::{Agent, Budget, LaneId, ProviderId};

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

fn durable_agent(secret: [u8; 32]) -> (Agent, ProviderId, LaneId) {
    let agent = Agent::with_secret(secret);
    agent.set_durable_capabilities(true);
    agent.set_record_seal_key([0x84; 32]);
    let provider = agent.register(Box::new(Echo));
    let lane = agent.create_lane("probe", Budget::default()).expect("lane");
    (agent, provider, lane)
}

fn durable(attrs: CapAttrs) -> CapAttrs {
    let mut attrs = attrs;
    attrs.persistence = CapPersistence::Durable;
    attrs
}

/// PROBE A: attenuation computes the child deadline in the *current* clock
/// domain but stamps it with the domain the parent was *minted* in.
#[test]
fn probe_a_attenuation_stamps_the_wrong_clock_domain() {
    let (source, provider, _lane) = durable_agent([0x42; 32]);
    let owner = admitted(b"owner");

    // 1. Unbounded durable parent minted in the virtual domain.
    let parent = source
        .mint_bound(&owner, provider, 0, durable(CapAttrs::new(&["echo"])))
        .expect("parent");
    // 2. The kernel switches to wall clock: now_ms jumps to the epoch.
    source.use_wall_clock(true);
    // 3. A child asks for a one-second lease: the deadline comes from the wall
    //    clock, but `wall_clock` is inherited from the parent.
    let child = source
        .attenuate(
            &parent,
            durable(CapAttrs::new(&["echo"]).with_ttl_ms(1_000)),
        )
        .expect("child");
    let record = source.export_capability(&child).expect("export");
    println!(
        "PROBE A: exported wall_clock={} expires_at={:?} source_now={} record_now={}",
        record.wall_clock,
        record.expires_at,
        source.now_ms(),
        0u64
    );

    // 4. Restore into a fresh kernel of the same authority domain that never
    //    used the wall clock: now_ms == 0.
    let (dest, _dest_provider, dest_lane) = durable_agent([0x42; 32]);
    let restored = dest.restore_capability(&record, &owner);
    match &restored {
        Ok(_) => println!("PROBE A: the mixed-domain record RESTORED into the virtual kernel"),
        Err(error) => println!("PROBE A: restore refused with {}", error.code()),
    }
    let restored = restored.expect("the record restores (the defect)");
    let remaining = record.expires_at.unwrap_or(0).saturating_sub(dest.now_ms());
    println!("PROBE A: remaining virtual lease = {remaining} ms (asked for 1000)");

    // 5. Advance the virtual clock past the requested lease.
    let peer = PeerIdentity::from_certificate(b"owner");
    dest.set_latency(5_000);
    for _ in 0..3 {
        let promise = dest
            .call_as(Some(&peer), dest_lane, &restored, "echo", Vec::new())
            .expect("call");
        dest.run();
        promise.value().expect("value");
    }
    println!(
        "PROBE A: after 3 wall-sized round trips now={} the lease is still live",
        dest.now_ms()
    );
    assert!(remaining > 1_000_000, "remaining lease is {remaining}");
}

/// PROBE B: a record carries the capability's budget *ceiling*, not what is
/// left of it, so export -> drop -> restore refills a spent grant.
#[test]
fn probe_b_export_then_restore_refills_a_spent_budget() {
    let (agent, provider, lane) = durable_agent([0x52; 32]);
    let owner = admitted(b"owner");
    let cap = agent
        .mint_bound(
            &owner,
            provider,
            0,
            durable(CapAttrs::new(&["echo"]).with_budget(Budget::calls(2))),
        )
        .expect("cap");
    let peer = PeerIdentity::from_certificate(b"owner");
    for _ in 0..2 {
        let promise = agent
            .call_as(Some(&peer), lane, &cap, "echo", Vec::new())
            .expect("call");
        agent.run();
        promise.value().expect("value");
    }
    let refused = agent
        .call_as(Some(&peer), lane, &cap, "echo", Vec::new())
        .expect_err("the 2-call grant is spent");
    println!("PROBE B: third call refused with {}", refused.code());
    let record = agent.export_capability(&cap).expect("export");
    println!(
        "PROBE B: exported budget.max_calls={} (2 already spent)",
        record.budget.max_calls
    );
    drop(cap);
    let restored = agent.restore_capability(&record, &owner).expect("restore");
    let mut accepted = 0;
    for _ in 0..2 {
        let promise = agent
            .call_as(Some(&peer), lane, &restored, "echo", Vec::new())
            .expect("refilled");
        agent.run();
        promise.value().expect("value");
        accepted += 1;
    }
    println!("PROBE B: the restored copy spent {accepted} more calls for a 2-call grant");
    assert_eq!(accepted, 2);
}

/// PROBE C: a panic inside `on_drop` is not guarded: the provider is dropped
/// out of the registry and `delivering` keeps its id.
#[test]
fn probe_c_a_panicking_on_drop_loses_the_provider() {
    struct PanicOnDrop;
    impl Provider for PanicOnDrop {
        fn name(&self) -> &'static str {
            "panic-on-drop"
        }
        fn methods(&self) -> Vec<String> {
            vec!["hold".to_string()]
        }
        fn mutating(&self, _method: &str) -> bool {
            false
        }
        fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
            Ok(Response::Value(Value::text("ok")))
        }
        fn on_drop(&mut self, _object: u64, _cap: active_rpc::CapId) {
            panic!("on_drop unwound");
        }
    }

    let agent = Agent::with_secret([0x62; 32]);
    let provider = agent.register(Box::new(PanicOnDrop));
    let doomed = agent
        .mint(provider, 1, CapAttrs::new(&["hold"]))
        .expect("first");
    let survivor = agent
        .mint(provider, 2, CapAttrs::new(&["hold"]))
        .expect("second");
    let lane = agent.create_lane("probe", Budget::default()).expect("lane");
    let unwound = catch_unwind(AssertUnwindSafe(|| drop(doomed)));
    assert!(unwound.is_err(), "the panic reaches the drop site");
    let promise = agent
        .call(lane, &survivor, "hold", Vec::new())
        .expect("queue");
    agent.run();
    let outcome = promise.value().map(|_| "ok".to_string());
    println!("PROBE C: the surviving capability now answers {outcome:?}");
    assert!(outcome.is_err(), "the provider survived the panic");
}

/// PROBE D: the tombstone ceiling turns a restore refusal into a budget error.
#[test]
fn probe_d_tombstone_ceiling_changes_the_restore_error() {
    let (source, provider, _lane) = durable_agent([0x72; 32]);
    let owner = admitted(b"owner");
    let cap = source
        .mint_bound(&owner, provider, 0, durable(CapAttrs::new(&["echo"])))
        .expect("cap");
    let record = source.export_capability(&cap).expect("export");
    drop(cap);
    for index in 0..active_rpc::kernel::MAX_TOMBSTONES {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&(index as u64).to_be_bytes());
        id[31] = 0xff;
        source.tombstone_record(id).expect("tombstone");
    }
    let error = source
        .restore_capability(&record, &owner)
        .expect_err("a full tombstone set refuses the restore");
    println!(
        "PROBE D: restore under a full tombstone set reports {} (expected rpc/persistence)",
        error.code()
    );
    let fresh = source.mint(provider, 0, durable(CapAttrs::new(&["echo"])));
    println!(
        "PROBE D: a new durable mint reports {:?}",
        fresh.err().map(|error| error.code().to_string())
    );
}

/// PROBE E: seal determinism across the JSON round trip, and the empty path
/// scope that export emits but restore refuses.
#[test]
fn probe_e_seal_round_trip_and_empty_path_scope() {
    let (agent, provider, _lane) = durable_agent([0x92; 32]);
    let owner = admitted(b"owner");
    let cap = agent
        .mint_bound(&owner, provider, 0, durable(CapAttrs::new(&["echo"])))
        .expect("cap");
    let record = agent.export_capability(&cap).expect("export");
    let text = record.to_json();
    let parsed = active_rpc::persistence::CapabilityRecord::from_json(&text).expect("parse");
    println!(
        "PROBE E: round-trip seal valid = {}, stable text = {}",
        parsed.seal_is_valid(&[0x84; 32]),
        parsed.to_json() == text
    );
    assert!(parsed.seal_is_valid(&[0x84; 32]));

    let scoped = agent
        .mint_bound(
            &owner,
            provider,
            0,
            durable(CapAttrs::new(&["echo"]).with_path("")),
        )
        .expect("scoped");
    let scoped_record = agent.export_capability(&scoped).expect("export");
    let restored = agent.restore_capability(&scoped_record, &owner);
    println!(
        "PROBE E: an exported empty path scope restores as {:?}",
        restored.as_ref().err().map(|error| error.code().to_string())
    );
    let reparsed =
        active_rpc::persistence::CapabilityRecord::from_json(&scoped_record.to_json());
    println!(
        "PROBE E: its own JSON re-parses as {:?}",
        reparsed.as_ref().err().map(|error| error.code().to_string())
    );
}

/// PROBE F: channel accounting after a destroy, and the lane charge.
#[test]
fn probe_f_channel_accounting_after_destroy() {
    let (agent, _provider, _lane) = durable_agent([0xa2; 32]);
    let lane = agent.create_lane("ch", Budget::default()).expect("lane");
    let channel = agent
        .create_channel("pipe", active_rpc::channel::Direction::Both)
        .expect("channel");
    agent
        .send(lane, channel, Value::text("payload"), &[])
        .expect("send");
    let queued = agent.channel(channel).expect("channel").queued_bytes();
    let lane_bytes = agent.lane(lane).expect("lane").bytes;
    agent.destroy_channel(channel).expect("destroy");
    let replacement = agent
        .create_channel("pipe2", active_rpc::channel::Direction::Both)
        .expect("channel");
    println!(
        "PROBE F: queued={queued} lane_bytes={lane_bytes} replacement_queued={} lane_bytes_after={}",
        agent.channel(replacement).expect("channel").queued_bytes(),
        agent.lane(lane).expect("lane").bytes
    );
    agent.destroy_lane(lane).expect("destroy lane");
    println!(
        "PROBE F: channel count {} after the lane died",
        agent.channel_count()
    );
}

/// PROBE G: a child that dies while its parent handle is alive still releases
/// the parent's descendant count exactly once.
#[test]
fn probe_g_descendants_balance() {
    let agent = Agent::with_secret([0xb2; 32]);
    let provider = agent.register(Box::new(Echo));
    let parent = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("parent");
    let first = agent
        .attenuate(&parent, CapAttrs::new(&["echo"]))
        .expect("first");
    let second = agent
        .attenuate(&parent, CapAttrs::new(&["echo"]))
        .expect("second");
    drop(first);
    // The parent record must still be there while `second` lives.
    println!(
        "PROBE G: parent alive after one child died = {:?}",
        agent.cap_attrs(&parent).is_ok()
    );
    drop(second);
    drop(parent);
    let dropped = agent
        .events()
        .iter()
        .filter(|event| matches!(event, active_rpc::Event::CapDropped(_)))
        .count();
    println!("PROBE G: CapDropped events = {dropped} (expected 3)");
    assert_eq!(dropped, 3);
}

