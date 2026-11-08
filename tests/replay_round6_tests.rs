//! R-12 replay rounds 6-12: a repeated revoke of an already-revoked subtree must
//! not re-walk it, must not scan the export pin table, and must not trust a
//! truncated replay trace.

use std::time::Instant;

use active_rpc::cap::{CapAttrs, CapPersistence};
use active_rpc::identity::{IdentityPolicy, PeerIdentity};
use active_rpc::replay::ReplayPackage;
use active_rpc::{AdmittedIdentity, Agent, Budget};

fn admitted(name: &[u8]) -> AdmittedIdentity {
    IdentityPolicy::default()
        .admit(Some(&PeerIdentity::from_certificate(name)), false)
        .expect("admitted")
}

fn durable() -> CapAttrs {
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    // A tiny grant: `export` reserves it from the parent, so thousands of
    // one-call reservations must fit the parent budget.
    attrs.budget.max_calls = 1;
    attrs.budget.max_bytes = 1;
    attrs
}

/// The first revoke walks the subtree; every later revoke of the same node must
/// be constant work. The reviewer's package used 16 000 children and 84 000
/// revokes (1.4e9 node visits); this fixture is smaller but the same shape, and
/// the bound is wide enough that only a re-walk can exceed it
/// (R-12 round 6, M1).
#[test]
fn repeated_revokes_of_a_revoked_subtree_are_linear() {
    let agent = Agent::new();
    let provider = agent.register(Box::new(Echo));
    let lane = agent
        .create_lane("replay", Budget::default())
        .expect("lane");
    let root = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("root");
    let mut children = Vec::with_capacity(8_000);
    for _ in 0..8_000 {
        children.push(
            agent
                .attenuate(&root, CapAttrs::new(&["echo"]))
                .expect("child"),
        );
    }
    // The first revoke marks all 8 001 nodes.
    agent.revoke(&root).expect("the first revoke");
    let started = Instant::now();
    for _ in 0..2_000 {
        // A revoked capability is refused, and the refusal must not re-walk.
        let _ = agent.revoke(&root);
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "2 000 repeated revokes of an 8 001-node subtree took {elapsed:?}: the walk is quadratic"
    );
    let _ = (lane, children);
}

/// A repeated revoke must not scan the export pin table either. A pin outlives
/// its exporting handle (the record stays restorable until its provider object
/// is reclaimed), so an unrelated revoke still has to look at the table once;
/// every later revoke of an already-revoked capability must not (R-12 round 12).
#[test]
fn repeated_revokes_with_a_surviving_pin_table_stay_linear() {
    const PINS: usize = 300;
    const REPEATS: usize = 100_000;

    let agent = Agent::new();
    agent.set_durable_capabilities(true);
    agent.set_record_seal_key([0x63; 32]);
    let owner = admitted(b"owner");
    let provider = agent.register(Box::new(Echo));
    let mut root_attrs = durable();
    root_attrs.budget.max_calls = u64::from(PINS as u32) + 1;
    root_attrs.budget.max_bytes = 1 << 20;
    let root = agent
        .mint_bound(&owner, provider, 0, root_attrs)
        .expect("root");
    for _ in 0..PINS {
        let child = agent.attenuate(&root, durable()).expect("child");
        agent.export_capability(&child).expect("export");
        // The exporting handle is dropped; the pin keeps the record's object
        // resident, so the table stays populated.
        drop(child);
    }
    let pins = agent.export_pin_count();
    assert_eq!(pins, PINS, "the fixture keeps one pin per exported record");

    // A separate capability whose repeated revocation is timed. Its first
    // revoke is allowed to run the orphan scan; the repeats are not.
    let victim = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("victim");
    agent.revoke(&victim).expect("the first revoke");
    let started = Instant::now();
    for _ in 0..REPEATS {
        let _ = agent.revoke(&victim);
    }
    let elapsed = started.elapsed();
    assert_eq!(agent.export_pin_count(), pins, "the pins survived");
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "{REPEATS} repeated revokes with {pins} pins took {elapsed:?}: the pin scan runs"
    );
}

/// A replay that loses events must refuse rather than return the truncated
/// trace: a package crafted to match that truncation would otherwise verify
/// (R-12 round 11, F1).
#[test]
fn a_replay_that_loses_events_refuses_instead_of_truncating() {
    use active_rpc::replay::Op;

    let mut ops = vec![Op::SetLatency(0)];
    ops.push(Op::Mint {
        methods: vec!["echo".to_string()],
        ttl_ms: None,
    });
    for _ in 0..17_000 {
        ops.push(Op::Attenuate {
            parent: 0,
            methods: vec!["echo".to_string()],
            ttl_ms: None,
        });
    }
    ops.push(Op::Revoke { cap: 0 });
    let package = ReplayPackage {
        latency_ms: 0,
        ops,
        trace: Vec::new(),
    };
    let error = package
        .replay_trace()
        .expect_err("the revoke overflows the event tape");
    assert_eq!(error.code(), "rpc/replay", "{error}");
    assert!(error.to_string().contains("lost events"), "{error}");
    let error = package.replay().expect_err("replay must refuse too");
    assert_eq!(error.code(), "rpc/replay", "{error}");
}

/// The diagnostic path still reports the operations the replay ran: the
/// recorder no longer keeps a second list, so it returns the package own ops
/// (R-12 round 10, F3).
#[test]
fn the_diagnostic_path_reports_the_package_operations() {
    use active_rpc::replay::Recorder;

    let mut recorder = Recorder::new(1).expect("recorder");
    let cap = recorder.mint(&["echo"], None).expect("mint");
    recorder.call(cap, "echo", 0).expect("call");
    let package = recorder.package().expect("package");
    let (trace, ops) = package.replay_trace().expect("replay trace");
    assert_eq!(
        ops, package.ops,
        "the diagnostic op list is the package own"
    );
    assert_eq!(trace.len(), package.trace.len(), "the trace is complete");
}

struct Echo;

impl active_rpc::kernel::Provider for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }
    fn methods(&self) -> Vec<String> {
        vec!["echo".to_string()]
    }
    fn mutating(&self, _method: &str) -> bool {
        false
    }
    fn invoke(
        &mut self,
        _object: u64,
        _call: &active_rpc::value::Call,
    ) -> active_rpc::Result<active_rpc::value::Response> {
        Ok(active_rpc::value::Response::Value(active_rpc::Value::text(
            "ok",
        )))
    }
}
