//! R-12 replay rounds 6-10: a repeated revoke of an already-revoked subtree must
//! not re-walk it, and must not scan the export pin table either.

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

/// A repeated revoke must not scan the export pin table either. The round-6
/// test has no `record_pins`, so it cannot see that scan; this one exports
/// 2 000 durable capabilities, drops their handles (so the pins survive the
/// root's revocation), and then revokes the same root 20 000 times (~40M pin
/// visits on the buggy path).
#[test]
fn repeated_revokes_with_a_pinned_export_table_stay_linear() {
    let agent = Agent::new();
    agent.set_durable_capabilities(true);
    agent.set_record_seal_key([0x63; 32]);
    let provider = agent.register(Box::new(Echo));
    let mut root_attrs = CapAttrs::new(&["echo"]);
    root_attrs.persistence = CapPersistence::Durable;
    let root = agent
        .mint_bound(&admitted(b"owner"), provider, 0, root_attrs)
        .expect("root");
    for _ in 0..2_000 {
        let mut attrs = CapAttrs::new(&["echo"]);
        attrs.persistence = CapPersistence::Durable;
        // A tiny grant: xport reserves it from the parent, and 2 000
        // one-call reservations must fit the parent budget.
        attrs.budget.max_calls = 1;
        attrs.budget.max_bytes = 1;
        let child = agent.attenuate(&root, attrs).expect("child");
        agent.export_capability(&child).expect("export");
        // The exported capability is dropped before the revocation, so the
        // record has no live capability and only the pin names it: the orphan
        // scan is the path under test.
        drop(child);
    }
    agent.revoke(&root).expect("the first revoke");
    let started = Instant::now();
    for _ in 0..20_000 {
        let _ = agent.revoke(&root);
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "20 000 repeated revokes with 2 000 pins took {elapsed:?}: the pin scan runs"
    );
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
