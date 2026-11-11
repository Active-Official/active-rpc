//! C-5.4 idempotency keys on the shipped call path.

use std::cell::Cell;
use std::rc::Rc;

use active_rpc::budget::Budget;
use active_rpc::cap::CapAttrs;
use active_rpc::kernel::MAX_IDEMPOTENCY;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::wire::Envelope;
use active_rpc::{Agent, Provider};

struct Counting {
    calls: Rc<Cell<usize>>,
    fail_next: Rc<Cell<bool>>,
    fail_withheld: Rc<Cell<bool>>,
}

impl Provider for Counting {
    fn name(&self) -> &'static str {
        "counting"
    }
    fn methods(&self) -> Vec<String> {
        vec!["mutate".into()]
    }
    fn mutating(&self, _method: &str) -> bool {
        true
    }
    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        self.calls.set(self.calls.get() + 1);
        if self.fail_withheld.replace(false) {
            return Err(active_rpc::Error::Provider {
                code: "provider/reply-withheld".into(),
            });
        }
        if self.fail_next.replace(false) {
            return Err(active_rpc::Error::Provider {
                code: "test/transient".into(),
            });
        }
        Ok(Response::Value(Value::Bool(true)))
    }
}

// Six handles: the whole fixture the tests share. The tuple is deliberate —
// a struct would make every test body longer for no gain — so the complexity
// lint is allowed here, as `too_many_arguments` is on the call wrappers this
// file exercises.
#[allow(clippy::type_complexity)]
fn setup() -> (
    Agent,
    active_rpc::CapHandle,
    active_rpc::LaneId,
    Rc<Cell<usize>>,
    Rc<Cell<bool>>,
    Rc<Cell<bool>>,
) {
    let agent = Agent::with_secret([0x55; 32]);
    let calls = Rc::new(Cell::new(0));
    let fail_next = Rc::new(Cell::new(false));
    let fail_withheld = Rc::new(Cell::new(false));
    let provider = agent
        .register(Box::new(Counting {
            calls: calls.clone(),
            fail_next: fail_next.clone(),
            fail_withheld: fail_withheld.clone(),
        }))
        .expect("register provider");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["mutate"]))
        .expect("cap");
    let lane = agent.create_lane("idem", Budget::default()).expect("lane");
    (agent, cap, lane, calls, fail_next, fail_withheld)
}

#[test]
fn the_same_key_returns_the_same_promise_and_runs_once() {
    let (agent, cap, lane, calls, _, _) = setup();
    let first = agent
        .call_idempotent(lane, &cap, "mutate", vec![], "order-1")
        .expect("first");
    let second = agent
        .call_idempotent(lane, &cap, "mutate", vec![], "order-1")
        .expect("second");
    assert_eq!(first.id(), second.id());
    agent.run();
    assert_eq!(first.value().expect("value"), Value::Bool(true));
    assert_eq!(calls.get(), 1);

    let third = agent
        .call_idempotent(lane, &cap, "mutate", vec![], "order-2")
        .expect("third");
    agent.run();
    third.value().expect("value");
    assert_eq!(calls.get(), 2);
}

#[test]
fn an_anonymous_peers_envelope_call_replays() {
    // F1-NF-06: an idempotent call that arrives as an envelope from a peer
    // that presents no identity must replay under the same key, like every
    // other idempotent call. The owner check compared the stored
    // `from_peer` flag against `peer.is_some()` alone, so the stored flag
    // (`true` for an envelope call) never matched on replay (`false` for
    // an anonymous peer) and every retry was refused as belonging to
    // another peer.
    let (agent, cap, lane, calls, _, _) = setup();
    let envelope = Envelope::request(1, "mutate", vec![]);
    let first = agent
        .call_idempotent_from_envelope(None, lane, &cap, &envelope, "peer-order-1")
        .expect("first");
    let second = agent
        .call_idempotent_from_envelope(None, lane, &cap, &envelope, "peer-order-1")
        .expect("the same envelope replays");
    assert_eq!(first.id(), second.id());
    agent.run();
    assert_eq!(first.value().expect("value"), Value::Bool(true));
    assert_eq!(calls.get(), 1);
}

#[test]
fn a_key_claimed_in_process_cannot_be_replayed_from_an_envelope() {
    // F1-NF-06 (guard): the owner check still distinguishes the two
    // origins. A key claimed by an in-process call is not replayable from
    // a peer envelope, and a key claimed from a peer envelope is not
    // replayable in-process — the fix only makes the two definitions of
    // "from a peer" agree with each other (R-11 round 14, F2).
    let (agent, cap, lane, calls, _, _) = setup();
    let first = agent
        .call_idempotent(lane, &cap, "mutate", vec![], "order-1")
        .expect("in-process claim");
    let envelope = Envelope::request(1, "mutate", vec![]);
    let replay = agent.call_idempotent_from_envelope(None, lane, &cap, &envelope, "order-1");
    assert_eq!(replay.unwrap_err().code(), "rpc/identity");
    agent.run();
    first.value().expect("value");
    assert_eq!(calls.get(), 1);
    // And the reverse: an envelope claim is not replayable in-process.
    let env_first = agent
        .call_idempotent_from_envelope(None, lane, &cap, &envelope, "peer-order-1")
        .expect("envelope claim");
    let in_process = agent.call_idempotent(lane, &cap, "mutate", vec![], "peer-order-1");
    assert_eq!(in_process.unwrap_err().code(), "rpc/identity");
    agent.run();
    env_first.value().expect("value");
    assert_eq!(calls.get(), 2);
}

#[test]
fn a_failed_attempt_is_not_cached() {
    let (agent, cap, lane, calls, fail_next, _) = setup();
    fail_next.set(true);
    let first = agent
        .call_idempotent(lane, &cap, "mutate", vec![], "retry")
        .expect("first");
    assert_eq!(first.value().unwrap_err().code(), "rpc/provider");
    let second = agent
        .call_idempotent(lane, &cap, "mutate", vec![], "retry")
        .expect("second");
    agent.run();
    second.value().expect("retry succeeds");
    assert_eq!(calls.get(), 2);
}

#[test]
fn an_empty_key_is_refused() {
    let (agent, cap, lane, _, _, _) = setup();
    assert_eq!(
        agent
            .call_idempotent(lane, &cap, "mutate", vec![Arg::text("x")], "")
            .unwrap_err()
            .code(),
        "rpc/invalid-argument"
    );
}

#[test]
fn filling_past_1024_keeps_the_oldest_claim_and_refuses_new_keys() {
    // RPC-06: the MAX_IDEMPOTENCY ceiling is fail-closed. The oldest claim
    // survives the fill, a 1,025th new key is refused with
    // `rpc/budget-exceeded`, and the refusal executes nothing.
    let (agent, cap, lane, calls, _, _) = setup();
    let first = agent
        .call_idempotent(lane, &cap, "mutate", vec![], "key-0000")
        .expect("first");
    agent.run();
    first.value().expect("value");
    assert_eq!(calls.get(), 1);
    for i in 1..MAX_IDEMPOTENCY {
        let p = agent
            .call_idempotent(lane, &cap, "mutate", vec![], &format!("key-{i:04}"))
            .expect("fill");
        agent.run();
        p.value().expect("value");
    }
    assert_eq!(calls.get(), MAX_IDEMPOTENCY);
    // The 1,025th distinct key is refused, and the refusal runs nothing.
    let refused = agent.call_idempotent(lane, &cap, "mutate", vec![], "key-1024");
    assert_eq!(refused.unwrap_err().code(), "rpc/budget-exceeded");
    assert_eq!(calls.get(), MAX_IDEMPOTENCY);
    // The oldest key still names its original promise: no double-apply.
    let retry = agent
        .call_idempotent(lane, &cap, "mutate", vec![], "key-0000")
        .expect("oldest key replays");
    assert_eq!(retry.id(), first.id());
    agent.run();
    retry.value().expect("value");
    assert_eq!(calls.get(), MAX_IDEMPOTENCY);
    // The newest admitted key replays too.
    let recent = agent
        .call_idempotent(lane, &cap, "mutate", vec![], "key-1023")
        .expect("newest key replays");
    agent.run();
    recent.value().expect("value");
    assert_eq!(calls.get(), MAX_IDEMPOTENCY);
}

#[test]
fn dead_claims_are_reclaimed_at_the_ceiling() {
    // RPC-06: claims whose promises failed are dead weight, not live claims.
    // Fill the table with two failed calls and the rest live; the next new
    // key is admitted by reclaiming the dead claims, a retry of a reclaimed
    // key is a fresh call (its slot was freed in the hit path), and only
    // once the table is full of live claims again is a new key refused.
    let (agent, cap, lane, calls, fail_next, _) = setup();
    let mut failed_ids = Vec::new();
    for key in ["dead-a", "dead-b"] {
        fail_next.set(true);
        let failed = agent
            .call_idempotent(lane, &cap, "mutate", vec![], key)
            .expect("failed claim");
        agent.run();
        assert!(failed.value().is_err());
        failed_ids.push(failed.id());
    }
    assert_eq!(calls.get(), 2);
    for i in 0..MAX_IDEMPOTENCY - 2 {
        let p = agent
            .call_idempotent(lane, &cap, "mutate", vec![], &format!("live-{i:04}"))
            .expect("fill");
        agent.run();
        p.value().expect("value");
    }
    assert_eq!(calls.get(), MAX_IDEMPOTENCY);
    // Admitted: the sweep reclaimed both dead claims to make room.
    let fresh = agent
        .call_idempotent(lane, &cap, "mutate", vec![], "after-dead")
        .expect("admitted after reclaiming the dead claims");
    agent.run();
    fresh.value().expect("value");
    assert_eq!(calls.get(), MAX_IDEMPOTENCY + 1);
    // A reclaimed key is gone, so retrying it is a fresh call, not a replay.
    let retry_dead = agent
        .call_idempotent(lane, &cap, "mutate", vec![], "dead-a")
        .expect("reclaimed key retries as a fresh call");
    assert_ne!(retry_dead.id(), failed_ids[0]);
    agent.run();
    retry_dead.value().expect("value");
    assert_eq!(calls.get(), MAX_IDEMPOTENCY + 2);
    // Now the table is full of live claims again: refused, runs nothing.
    let refused = agent.call_idempotent(lane, &cap, "mutate", vec![], "one-more");
    assert_eq!(refused.unwrap_err().code(), "rpc/budget-exceeded");
    assert_eq!(calls.get(), MAX_IDEMPOTENCY + 2);
}

#[test]
fn a_cancelled_claim_is_reclaimed_at_the_ceiling() {
    // RPC-06: a cancelled call's claim is dead too. Cancel one claim, fill
    // the rest of the table with live calls, and the next new key is
    // admitted by reclaiming the cancelled claim.
    let (agent, cap, lane, calls, _, _) = setup();
    let cancelled = agent
        .call_idempotent(lane, &cap, "mutate", vec![], "cancelled-key")
        .expect("claim");
    agent.cancel(&cancelled).expect("cancel");
    for i in 0..MAX_IDEMPOTENCY - 1 {
        let p = agent
            .call_idempotent(lane, &cap, "mutate", vec![], &format!("live-{i:04}"))
            .expect("fill");
        agent.run();
        p.value().expect("value");
    }
    // The cancelled call never ran: only the live fills executed.
    assert_eq!(calls.get(), MAX_IDEMPOTENCY - 1);
    let fresh = agent
        .call_idempotent(lane, &cap, "mutate", vec![], "after-cancel")
        .expect("admitted after reclaiming the cancelled claim");
    agent.run();
    fresh.value().expect("value");
    assert_eq!(calls.get(), MAX_IDEMPOTENCY);
}

#[test]
fn a_withheld_reply_claim_is_live_and_never_reclaimed() {
    // RPC-06: a withheld reply means the write landed, so its claim is live:
    // it is never reclaimed to make room, a new key at the ceiling is
    // refused even though a dead claim would have been reclaimed, and the
    // withheld key still replays its original outcome, not a fresh call.
    let (agent, cap, lane, calls, _, fail_withheld) = setup();
    fail_withheld.set(true);
    let withheld = agent
        .call_idempotent(lane, &cap, "mutate", vec![], "withheld-key")
        .expect("withheld claim");
    agent.run();
    let error = withheld.value().expect_err("the reply was withheld");
    assert_eq!(
        error.provider_code(),
        Some("provider/reply-withheld"),
        "{error}"
    );
    assert_eq!(calls.get(), 1);
    for i in 0..MAX_IDEMPOTENCY - 1 {
        let p = agent
            .call_idempotent(lane, &cap, "mutate", vec![], &format!("live-{i:04}"))
            .expect("fill");
        agent.run();
        p.value().expect("value");
    }
    assert_eq!(calls.get(), MAX_IDEMPOTENCY);
    let refused = agent.call_idempotent(lane, &cap, "mutate", vec![], "one-more");
    assert_eq!(refused.unwrap_err().code(), "rpc/budget-exceeded");
    assert_eq!(calls.get(), MAX_IDEMPOTENCY);
    let replay = agent
        .call_idempotent(lane, &cap, "mutate", vec![], "withheld-key")
        .expect("withheld key replays");
    assert_eq!(replay.id(), withheld.id());
    agent.run();
    let replayed = replay.value().expect_err("withheld outcome replays");
    assert_eq!(
        replayed.provider_code(),
        Some("provider/reply-withheld"),
        "{replayed}"
    );
    assert_eq!(calls.get(), MAX_IDEMPOTENCY);
}
