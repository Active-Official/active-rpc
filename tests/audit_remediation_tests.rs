//! Regressions for the 2026-11-03 audit remediation package
//! (`G:\AUDIT\audit-remediation`). Each test fails on the pre-fix tree and
//! pins an invariant the independent auditors named.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use active_rpc::cap::CapAttrs;
#[cfg(feature = "test-utils")]
use active_rpc::cap::CapPersistence;
use active_rpc::kernel::Provider;
use active_rpc::persistence::MemoryRecordStore;
#[cfg(windows)]
use active_rpc::value::Arg;
use active_rpc::value::{Call, Response, Value};
#[cfg(feature = "test-utils")]
use active_rpc::{AdmittedIdentity, IdentityPolicy, PeerIdentity};
use active_rpc::{Agent, Budget, CapHandle, Error, LaneId};

/// A provider that counts calls and echoes.
struct Echo(Arc<AtomicUsize>);

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
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Response::Value(Value::text(call.method.clone())))
    }
}

fn echo_agent() -> (Agent, CapHandle, LaneId, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let agent = Agent::with_secret([0x7b; 32]);
    let provider = agent
        .register(Box::new(Echo(Arc::clone(&calls))))
        .expect("register provider");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.budget = Budget {
        max_bytes: 1 << 20,
        ..Budget::default()
    };
    let cap = agent.mint(provider, 0, attrs).expect("cap");
    let lane = agent
        .create_lane(
            "audit",
            Budget {
                max_bytes: 1 << 20,
                ..Budget::default()
            },
        )
        .expect("lane");
    (agent, cap, lane, calls)
}

#[cfg(feature = "test-utils")]
fn admitted(name: &[u8]) -> AdmittedIdentity {
    IdentityPolicy::default()
        .admit(Some(&PeerIdentity::from_certificate_for_test(name)), false)
        .expect("admitted")
}

/// ARPC-001: dispatch revalidates the *complete* request, payload included,
/// against the budget that exists when it runs.
#[test]
fn a_narrowed_lane_refuses_a_queued_payload() {
    let (agent, cap, lane, calls) = echo_agent();
    let body = vec![0u8; 64 * 1024];
    let promise = agent
        .call_idempotent_as_with_body(None, lane, &cap, "echo", Vec::new(), &body, "audit-payload")
        .expect("queued");
    // The args are empty, so an args-only recheck passes; the payload is what
    // must be refused.
    agent
        .attenuate_lane(
            lane,
            Budget {
                max_bytes: 32 * 1024,
                ..Budget::default()
            },
        )
        .expect("narrowed");
    agent.run();
    let error = promise
        .value()
        .expect_err("the payload no longer fits the lane");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    assert_eq!(calls.load(Ordering::SeqCst), 0, "the provider ran");
}

/// ARPC-010: `claim` is atomic, so exactly one contender takes a record id.
#[test]
fn claim_has_exactly_one_winner() {
    use std::sync::Barrier;

    use active_rpc::persistence::RecordStore;

    // A store shared behind a lock: the trait's `&mut self` serialises the
    // calls, and `MemoryRecordStore::claim` must still admit only one.
    let store = Arc::new(std::sync::Mutex::new(MemoryRecordStore::new()));
    let barrier = Arc::new(Barrier::new(2));
    let id = [7u8; 32];
    let mut contenders = Vec::new();
    for _ in 0..2 {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        contenders.push(std::thread::spawn(move || {
            barrier.wait();
            let mut store = store.lock().expect("store");
            store.claim(&id).is_ok()
        }));
    }
    let winners: Vec<bool> = contenders
        .into_iter()
        .map(|handle| handle.join().expect("thread"))
        .collect();
    assert_eq!(
        winners.iter().filter(|won| **won).count(),
        1,
        "one record, one winner: {winners:?}"
    );
}

/// AR-02: an out-of-band answer for a cancelled promise charges nothing.
#[test]
fn resolve_as_after_cancel_does_not_charge() {
    let (agent, cap, lane, _calls) = echo_agent();
    let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("queued");
    let before = agent.remaining_bytes(&cap).expect("meter");
    agent.cancel(&promise).expect("cancel");
    let error = agent
        .resolve_as(None, &promise, Value::text("x".repeat(4_096)))
        .expect_err("a cancelled promise is not settled out of band");
    assert_eq!(error.code(), "rpc/promise-cancelled", "{error}");
    assert_eq!(
        agent.remaining_bytes(&cap).expect("meter"),
        before,
        "a refused out-of-band resolve charged egress"
    );
}

/// AR-03: dropping the last handle of an exported durable capability is
/// observable, because the sealed record is still restorable.
#[cfg(feature = "test-utils")]
#[test]
fn dropping_an_exported_capability_reports_the_orphan() {
    let agent = Agent::with_secret([0x7d; 32]);
    agent.set_record_seal_key([0x7e; 32]);
    agent.set_durable_capabilities(true);
    let provider = agent
        .register(Box::new(Echo(Arc::new(AtomicUsize::new(0)))))
        .expect("register provider");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let owner = admitted(b"owner");
    let cap = agent
        .mint_bound(&owner, provider, 0, attrs)
        .expect("durable cap");
    let record = agent.export_capability(&cap).expect("export");
    assert_eq!(record.record_id.len(), 32);
    drop(cap);
    agent.run();
    let orphaned = agent
        .events()
        .iter()
        .any(|event| matches!(event, active_rpc::Event::CapRecordOrphaned(_)));
    assert!(orphaned, "the orphaned exported record was not reported");
}

/// AR-04: a leaf renewal moves a bound capability to the new fingerprint
/// without changing its authority.
#[cfg(feature = "test-utils")]
#[test]
fn a_rotated_certificate_can_rebind_a_capability() {
    let agent = Agent::with_secret([0x7f; 32]);
    let calls = Arc::new(AtomicUsize::new(0));
    let provider = agent
        .register(Box::new(Echo(Arc::clone(&calls))))
        .expect("register provider");
    let owner = admitted(b"old-owner");
    let cap = agent
        .mint_bound(&owner, provider, 0, CapAttrs::new(&["echo"]))
        .expect("bound cap");
    let lane = agent
        .create_lane("rotation", Budget::default())
        .expect("lane");
    let renewed = admitted(b"new-owner");
    agent
        .reintroduce_to(&cap, owner.identity(), &renewed)
        .expect("rebind");

    // The old peer is refused, the new one is admitted, and the authority is
    // the same.
    let error = agent
        .call_as(Some(owner.identity()), lane, &cap, "echo", Vec::new())
        .expect_err("the old fingerprint is no longer bound");
    assert_eq!(error.code(), "rpc/identity", "{error}");
    let promise = agent
        .call_as(Some(renewed.identity()), lane, &cap, "echo", Vec::new())
        .expect("the rotated peer is admitted");
    agent.run();
    assert!(promise.value().is_ok());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// ARPC-004: the Windows cleanup path never launches a helper chosen through
/// the process environment.
#[cfg(windows)]
#[test]
fn a_poisoned_system_root_does_not_run_a_planted_helper() {
    let dir =
        std::env::temp_dir().join(format!("active-rpc-audit-taskkill-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let planted_dir = dir.join("System32");
    std::fs::create_dir_all(&planted_dir).expect("dir");
    let marker = dir.join("planted-ran");
    // A fake taskkill that records its execution.
    std::fs::write(
        planted_dir.join("taskkill.exe"),
        format!("@echo off\r\n>>\"{}\" echo ran\r\n", marker.display()),
    )
    .expect("planted helper");

    // The plugin talks to no real program: construct via the test-only path by
    // poisoning the environment and running a timed-out child.
    let previous = std::env::var_os("SystemRoot");
    std::env::set_var("SystemRoot", &dir);
    let program = "C:\\Windows\\System32\\cmd.exe";
    let mut tool = active_rpc::tool::LocalProcess::new(program, &["*"])
        .expect("absolute program")
        .with_allow_any_arg();
    tool.timeout_ms = 50;
    let mut call = Call::new(
        "run",
        vec![Arg::text("/C"), Arg::text("ping -n 30 127.0.0.1 > NUL")],
    );
    call.tool_allows_process = true;
    let _ = tool.invoke(0, &call);
    match previous {
        Some(value) => std::env::set_var("SystemRoot", value),
        None => std::env::remove_var("SystemRoot"),
    }
    assert!(
        !marker.exists(),
        "the cleanup ran a taskkill planted through SystemRoot"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A helper that names the types so an unused import is caught early.
#[allow(dead_code)]
fn _types(_: &Error) {}
