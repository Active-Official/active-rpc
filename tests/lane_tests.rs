//! R-05 lanes and channels: lifecycle, capacity, accounting and the boundary a
//! lane does and does not draw.
//!
//! Every test here fails against the tree before its fix.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use active_rpc::cap::CapAttrs;
use active_rpc::channel::{Direction, MAX_QUEUED_BYTES};
use active_rpc::kernel::{Provider, MAX_OBJECT_NAME_BYTES};
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::{Agent, Budget, LaneId, PromiseHandle};

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

fn agent() -> (Agent, active_rpc::ProviderId) {
    let agent = Agent::with_secret([0x61; 32]);
    let provider = agent.register(Box::new(Echo));
    (agent, provider)
}

/// Destroying a lane with a full queue must not scan the queue per job.
#[test]
fn destroying_a_full_lane_does_not_block_the_kernel() {
    let (agent, provider) = agent();
    let cap = agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["echo"]).with_budget(Budget {
                max_calls: 50_000,
                max_bytes: u64::MAX,
                ..Budget::default()
            }),
        )
        .expect("cap");
    let busy = agent
        .create_lane(
            "busy",
            Budget {
                max_calls: 50_000,
                max_bytes: u64::MAX,
                ..Budget::default()
            },
        )
        .expect("lane");
    let other = agent.create_lane("other", Budget::default()).expect("lane");
    for _ in 0..40_000 {
        agent.call(busy, &cap, "echo", Vec::new()).expect("queued");
    }
    let start = std::time::Instant::now();
    agent.destroy_lane(busy).expect("destroy");
    let elapsed = start.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "destroying a full lane took {elapsed:?}"
    );
    // The rest of the kernel still works.
    let promise = agent.call(other, &cap, "echo", Vec::new()).expect("call");
    agent.run();
    promise.value().expect("value");
}

/// A publish the channel would refuse must not spend the grant.
#[test]
fn a_publish_refused_on_a_full_channel_charges_nothing() {
    let (agent, provider) = agent();
    let channel = agent
        .create_channel("full", Direction::Both)
        .expect("channel");
    let lane = agent
        .create_lane(
            "fill",
            Budget {
                max_bytes: u64::MAX,
                // The filler is one 64 MiB message, so the per-value ceiling
                // has to allow it: this test is about the channel's byte
                // ceiling, not the shape ceilings.
                max_value_size: u64::MAX,
                ..Budget::default()
            },
        )
        .expect("lane");
    // Fill the channel to its byte ceiling with one message.
    // A text value costs its tag, a length prefix and its bytes: the message
    // fills the channel exactly.
    let filler = Value::text("x".repeat(MAX_QUEUED_BYTES as usize - 5));
    agent
        .send(lane, channel, filler, &[])
        .expect("the ceiling itself fits");
    let mut attrs = CapAttrs::new(&["echo"]).allow_publish();
    attrs.budget.max_bytes = 16;
    attrs.budget.max_calls = 1;
    let cap = agent.mint(provider, 0, attrs).expect("small cap");
    let publish_lane = agent.create_lane("pub", Budget::default()).expect("lane");
    agent.subscribe(publish_lane, channel).expect("subscribe");
    let error = agent
        .publish(publish_lane, channel, &cap, "t", Value::text("0123456789"))
        .expect_err("the channel is full");
    assert_eq!(error.code(), "rpc/backpressure", "{error}");

    // Drain, then the same grant still works: the refusal charged nothing.
    agent
        .recv(publish_lane, channel)
        .expect("recv")
        .expect("message");
    agent
        .publish(publish_lane, channel, &cap, "t", Value::text("0123456789"))
        .expect("the grant survived the refusal");
}

/// Closing a channel through the agent stops sends; a snapshot cannot.
#[test]
fn closing_a_channel_stops_sends() {
    let (agent, _provider) = agent();
    let channel = agent
        .create_channel("closable", Direction::Both)
        .expect("channel");
    let lane = agent
        .create_lane("closer", Budget::default())
        .expect("lane");
    agent.close_channel(channel).expect("close");
    let error = agent
        .send(lane, channel, Value::text("x"), &[])
        .expect_err("a closed channel refuses sends");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
}

/// A lane is a budget scope, not an authority boundary: authority lives on the
/// capability.
#[test]
fn a_lane_is_not_an_authority_boundary() {
    let (agent, provider) = agent();
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let first = agent.create_lane("first", Budget::default()).expect("lane");
    let second = agent
        .create_lane("second", Budget::default())
        .expect("lane");
    let promise = agent.call(first, &cap, "echo", Vec::new()).expect("call");
    agent.run();
    promise.value().expect("value");
    // The same capability works from another lane: a lane does not own caps.
    let promise = agent.call(second, &cap, "echo", Vec::new()).expect("call");
    agent.run();
    promise.value().expect("value");
}

/// One message transfers one reference per capability.
#[test]
fn a_message_cannot_transfer_the_same_capability_twice() {
    let (agent, provider) = agent();
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let lane = agent.create_lane("dup", Budget::default()).expect("lane");
    let channel = agent
        .create_channel("dup", Direction::Both)
        .expect("channel");
    let error = agent
        .send(lane, channel, Value::text("x"), &[cap.clone(), cap.clone()])
        .expect_err("the same capability twice is not a transfer");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");

    agent
        .send(lane, channel, Value::text("x"), &[cap])
        .expect("one transfer");
    assert_eq!(agent.metrics().transfers, 1);
}

/// Names and subscriptions are bounded.
#[test]
fn names_and_subscriptions_are_bounded() {
    let (agent, _provider) = agent();
    let long = "n".repeat(MAX_OBJECT_NAME_BYTES + 1);
    let error = agent
        .create_channel(long.clone(), Direction::Both)
        .expect_err("a channel name is bounded");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
    let error = agent
        .create_lane(long, Budget::default())
        .expect_err("a lane name is bounded");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
}

/// A send is lane traffic: it consumes the lane's byte budget and a call.
#[test]
fn a_send_is_lane_traffic() {
    let (agent, _provider) = agent();
    let lane = agent
        .create_lane(
            "tight",
            Budget {
                max_bytes: 32,
                max_calls: 1,
                ..Budget::default()
            },
        )
        .expect("lane");
    let channel = agent
        .create_channel("tight", Direction::Both)
        .expect("channel");
    agent
        .send(lane, channel, Value::text("first"), &[])
        .expect("within the grant");
    let error = agent
        .send(lane, channel, Value::text("second"), &[])
        .expect_err("the lane call budget is spent");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    let state = agent.lane(lane).expect("lane");
    assert_eq!(state.completed, 1);
    assert_eq!(state.pending, 0);
}

/// A destroyed channel releases its queued accounting, so the next channel can
/// use the full budget.
#[test]
fn a_destroyed_channel_releases_its_bytes() {
    let (agent, _provider) = agent();
    let lane = agent.create_lane("churn", Budget::default()).expect("lane");
    let first = agent
        .create_channel("first", Direction::Both)
        .expect("channel");
    let value = Value::text("y".repeat(1 << 20));
    agent.send(lane, first, value.clone(), &[]).expect("send");
    agent.destroy_channel(first).expect("destroy");
    let second = agent
        .create_channel("second", Direction::Both)
        .expect("channel");
    agent
        .send(lane, second, value, &[])
        .expect("send after destroy");
}

/// A refusal is counted, and the counter is not a queue length.
#[test]
fn refusals_are_counted() {
    let (agent, _provider) = agent();
    let lane = agent.create_lane("refuse", Budget::calls(1)).expect("lane");
    let channel = agent
        .create_channel("refuse", Direction::Both)
        .expect("channel");
    agent
        .send(lane, channel, Value::text("one"), &[])
        .expect("first");
    let before = agent.metrics().calls_refused;
    let error = agent
        .send(lane, channel, Value::text("two"), &[])
        .expect_err("the lane budget is spent");
    assert_eq!(error.code(), "rpc/budget-exceeded");
    assert_eq!(
        agent.metrics().calls_refused,
        before + 1,
        "a refused send is not counted"
    );
}

/// Destroys its own lane from inside a call, then counts any work that still
/// runs on that lane.
struct Killer {
    agent: Rc<RefCell<Option<Agent>>>,
    victim: Rc<Cell<Option<u64>>>,
    work: Rc<Cell<usize>>,
}

impl Provider for Killer {
    fn name(&self) -> &'static str {
        "killer"
    }

    fn methods(&self) -> Vec<String> {
        vec!["kill".to_string(), "work".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, call: &Call) -> active_rpc::Result<Response> {
        if call.method == "kill" {
            let agent = self.agent.borrow();
            let agent = agent.as_ref().expect("the agent is installed");
            let lane = self.victim.get().expect("the lane is installed");
            agent.destroy_lane(LaneId(lane)).expect("destroy the lane");
            Ok(Response::Value(Value::text("killed")))
        } else {
            self.work.set(self.work.get() + 1);
            Ok(Response::Value(Value::text("worked")))
        }
    }
}

#[test]
fn destroying_a_lane_mid_batch_settles_its_running_call_once() {
    let agent = Agent::with_secret([0x7c; 32]);
    let slot: Rc<RefCell<Option<Agent>>> = Rc::new(RefCell::new(None));
    let victim = Rc::new(Cell::new(None));
    let work = Rc::new(Cell::new(0usize));
    let provider = agent.register(Box::new(Killer {
        agent: Rc::clone(&slot),
        victim: Rc::clone(&victim),
        work: Rc::clone(&work),
    }));
    *slot.borrow_mut() = Some(agent.clone());
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["kill", "work"]))
        .expect("cap");
    let lane = agent
        .create_lane("victim", Budget::default())
        .expect("lane");
    victim.set(Some(lane.0));

    // Both jobs land in one batch: the first destroys the lane as it runs.
    let kill = agent.call(lane, &cap, "kill", Vec::new()).expect("kill");
    let queued_work = agent.call(lane, &cap, "work", Vec::new()).expect("work");
    agent.run();

    // The provider ran and destroyed its own lane, so the response cannot be
    // delivered: egress is charged to the lane, and the lane no longer exists
    // (R-02 round 4 #2). The promise is settled once, by its own dispatch.
    let error = kill
        .value()
        .expect_err("a destroyed lane cannot deliver the response");
    assert_eq!(error.code(), "rpc/unknown-lane");
    let error = queued_work
        .value()
        .expect_err("queued work on a destroyed lane is refused");
    assert_eq!(error.code(), "rpc/unknown-lane");
    assert_eq!(
        work.get(),
        0,
        "the provider ran work on a lane destroyed before its job"
    );
    assert_eq!(
        agent.metrics().promises_double_settled,
        0,
        "a running job's promise was settled twice"
    );
}

/// Destroys its own lane while a dependent job is still queued, and records
/// how many waiters the dependency had at that moment.
struct ChainKiller {
    agent: Rc<RefCell<Option<Agent>>>,
    victim: Rc<Cell<Option<u64>>>,
    dependency: Rc<RefCell<Option<PromiseHandle>>>,
    observed: Rc<Cell<Option<u32>>>,
}

impl Provider for ChainKiller {
    fn name(&self) -> &'static str {
        "chain-killer"
    }

    fn methods(&self) -> Vec<String> {
        vec!["zero".to_string(), "first".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, call: &Call) -> active_rpc::Result<Response> {
        if call.method == "first" {
            let agent = self.agent.borrow();
            let agent = agent.as_ref().expect("the agent is installed");
            let lane = self.victim.get().expect("the lane is installed");
            agent.destroy_lane(LaneId(lane)).expect("destroy the lane");
            let dependency = self.dependency.borrow();
            let dependency = dependency.as_ref().expect("the dependency is installed");
            self.observed.set(Some(agent.promise_waiters(dependency)));
        }
        Ok(Response::Value(Value::text("ok")))
    }
}

#[test]
fn destroying_a_lane_does_not_release_a_running_jobs_dependency() {
    // Round 2 (#2): the destroy swept the deps of every job on the lane,
    // including the running one, and the dispatch then released them again at
    // settlement. `saturating_sub` hid the second release, but the dependency's
    // waiter count dropped to zero while a running job still needed it, which
    // makes the record trim-eligible too early.
    let agent = Agent::with_secret([0x7f; 32]);
    let slot: Rc<RefCell<Option<Agent>>> = Rc::new(RefCell::new(None));
    let victim = Rc::new(Cell::new(None));
    let dependency: Rc<RefCell<Option<PromiseHandle>>> = Rc::new(RefCell::new(None));
    let observed = Rc::new(Cell::new(None));
    let provider = agent.register(Box::new(ChainKiller {
        agent: Rc::clone(&slot),
        victim: Rc::clone(&victim),
        dependency: Rc::clone(&dependency),
        observed: Rc::clone(&observed),
    }));
    *slot.borrow_mut() = Some(agent.clone());
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["zero", "first"]))
        .expect("cap");
    let lane = agent.create_lane("chain", Budget::default()).expect("lane");
    victim.set(Some(lane.0));
    let zero = agent.call(lane, &cap, "zero", Vec::new()).expect("zero");
    *dependency.borrow_mut() = Some(zero.clone());
    // The second job holds the first job's promise as a dependency.
    let _first = agent
        .call(lane, &cap, "first", vec![Arg::Promise(zero.id())])
        .expect("first");
    agent.run();

    assert_eq!(
        observed.get(),
        Some(1),
        "the running job's dependency lost its waiter when the lane was destroyed"
    );
}

#[test]
fn lane_and_channel_names_are_validated_text() {
    // Round 2 (#3): a lane name was checked for length only, while a channel
    // name and a topic were checked as text. A name is a label an operator
    // reads, and a control character or a line separator can forge a record.
    let (agent, _provider) = agent();
    assert!(agent.create_lane("", Budget::default()).is_err());
    assert!(agent
        .create_lane("bad\u{2028}name", Budget::default())
        .is_err());
    assert!(agent.create_lane("fine", Budget::default()).is_ok());
    // The refusal names the bound the constant actually enforces.
    let error = agent
        .create_lane("n".repeat(MAX_OBJECT_NAME_BYTES + 1), Budget::default())
        .expect_err("an over-long name is refused");
    assert!(
        error.to_string().contains("1..=128"),
        "unexpected refusal: {error}"
    );
}

#[test]
fn unsubscribing_from_a_missing_channel_is_refused() {
    let (agent, _provider) = agent();
    let lane = agent.create_lane("gone", Budget::default()).expect("lane");
    let channel = agent
        .create_channel("gone", Direction::Both)
        .expect("channel");
    agent.destroy_channel(channel).expect("destroy");
    let error = agent
        .unsubscribe(lane, channel)
        .expect_err("a destroyed channel cannot be unsubscribed");
    assert_eq!(error.code(), "rpc/unknown-channel");
}

#[test]
fn subscription_lifecycle_is_on_the_tape() {
    let (agent, _provider) = agent();
    let lane = agent.create_lane("tape", Budget::default()).expect("lane");
    let channel = agent
        .create_channel("tape", Direction::Both)
        .expect("channel");
    agent.subscribe(lane, channel).expect("subscribe");
    agent.unsubscribe(lane, channel).expect("unsubscribe");
    agent.close_channel(channel).expect("close");
    let json = agent.trace_json();
    for event in [
        "channel.created",
        "channel.subscribed",
        "channel.unsubscribed",
        "channel.closed",
    ] {
        assert!(
            json.contains(&format!("\"event\":\"{event}\"")),
            "{event} is not on the tape: {json}"
        );
    }
}

#[test]
fn a_lane_can_release_a_subscription() {
    // Round 2 (#4): subscriptions only grew, so a lane at the per-lane ceiling
    // could never subscribe again, and read access could not be withdrawn.
    let (agent, _provider) = agent();
    let lane = agent
        .create_lane("release", Budget::default())
        .expect("lane");
    let channel = agent
        .create_channel("release", Direction::Both)
        .expect("channel");
    agent.subscribe(lane, channel).expect("subscribe");
    agent.unsubscribe(lane, channel).expect("unsubscribe");
    assert_eq!(agent.channel(channel).expect("channel").subscribers, 0);
    let error = agent
        .recv(lane, channel)
        .expect_err("the lane is no longer subscribed");
    assert_eq!(error.code(), "rpc/unknown-channel");
    // And the subscription slot is free again.
    agent.subscribe(lane, channel).expect("resubscribe");
}

#[test]
fn destroying_a_channel_reports_its_backlog() {
    // Round 2 (#5): a destroy dropped queued messages with no event, so an
    // operator could not tell a destroy with a backlog from an empty one.
    let (agent, _provider) = agent();
    let lane = agent
        .create_lane("backlog", Budget::default())
        .expect("lane");
    let channel = agent
        .create_channel("backlog", Direction::Both)
        .expect("channel");
    agent
        .send(lane, channel, Value::text("one"), &[])
        .expect("send");
    agent
        .send(lane, channel, Value::text("two"), &[])
        .expect("send");
    agent.destroy_channel(channel).expect("destroy");
    let json = agent.trace_json();
    assert!(
        json.contains("\"event\":\"channel.destroyed\""),
        "the destroy is not on the tape: {json}"
    );
    assert!(
        json.contains("\"detail\":\"2\""),
        "the dropped count is not on the tape: {json}"
    );
}

#[test]
fn receiving_on_a_destroyed_lane_is_unknown_lane() {
    // Round 4 (#1): every other operation answers `rpc/unknown-lane` for a lane
    // that is gone; a receive reported the channel class instead.
    let (agent, _provider) = agent();
    let lane = agent.create_lane("gone", Budget::default()).expect("lane");
    let channel = agent
        .create_channel("gone", Direction::Both)
        .expect("channel");
    agent.subscribe(lane, channel).expect("subscribe");
    agent.destroy_lane(lane).expect("destroy");
    let error = agent
        .recv(lane, channel)
        .expect_err("a destroyed lane cannot receive");
    assert_eq!(error.code(), "rpc/unknown-lane");
}

#[test]
fn a_no_op_subscription_change_is_not_an_event() {
    // Round 4 (#2): an event per call let a subscribe/unsubscribe loop evict the
    // bounded tape.
    let (agent, _provider) = agent();
    let lane = agent.create_lane("quiet", Budget::default()).expect("lane");
    let channel = agent
        .create_channel("quiet", Direction::Both)
        .expect("channel");
    agent.subscribe(lane, channel).expect("subscribe");
    agent.subscribe(lane, channel).expect("resubscribe");
    agent.unsubscribe(lane, channel).expect("unsubscribe");
    agent.unsubscribe(lane, channel).expect("unsubscribe again");
    let json = agent.trace_json();
    assert_eq!(
        json.matches("\"event\":\"channel.subscribed\"").count(),
        1,
        "a repeat subscription emitted another event: {json}"
    );
    assert_eq!(
        json.matches("\"event\":\"channel.unsubscribed\"").count(),
        1,
        "a repeat unsubscribe emitted another event: {json}"
    );
}

#[test]
fn destroying_a_full_lane_does_not_flood_the_tape() {
    // Round 4 (#3): a per-job event each meant one destroy could write tens of
    // thousands of records and evict the whole tape.
    let (agent, _provider) = agent();
    let lane = agent.create_lane("flood", Budget::default()).expect("lane");
    let channel = agent
        .create_channel("flood", Direction::Both)
        .expect("channel");
    agent.subscribe(lane, channel).expect("subscribe");
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    for _ in 0..2_000 {
        agent.call(lane, &cap, "echo", Vec::new()).expect("queued");
    }
    let before = agent.total_events();
    agent.destroy_lane(lane).expect("destroy");
    let after = agent.total_events();
    assert!(
        after - before <= 3,
        "destroying a lane of 2 000 jobs wrote {} events",
        after - before
    );
    let json = agent.trace_json();
    assert!(
        json.contains("\"event\":\"lane.destroyed\""),
        "the destroy is not on the tape: {json}"
    );
    assert!(
        json.contains("\"detail\":\"2000\""),
        "the dropped-job count is not on the tape: {json}"
    );
}

#[test]
fn closing_a_receive_only_channel_is_an_event() {
    // Round 5 (#1): the event was gated on `can_send()`, which is false from the
    // start for a receive-only channel, so its close changed the stats silently.
    let (agent, _provider) = agent();
    let lane = agent.create_lane("ro", Budget::default()).expect("lane");
    let channel = agent
        .create_channel("ro", Direction::Receive)
        .expect("channel");
    agent.subscribe(lane, channel).expect("subscribe");
    agent.close_channel(channel).expect("close");
    assert!(agent.channel(channel).expect("channel").closed);
    let json = agent.trace_json();
    assert!(
        json.contains("\"event\":\"channel.closed\""),
        "closing a receive-only channel is not on the tape: {json}"
    );
}

#[test]
fn a_receive_filter_is_validated_text() {
    // Round 5 (#2): `recv_topic` answered `Ok(None)` for a filter the channel
    // could never hold, while publish refuses the same text.
    let (agent, _provider) = agent();
    let lane = agent
        .create_lane("filter", Budget::default())
        .expect("lane");
    let channel = agent
        .create_channel("filter", Direction::Both)
        .expect("channel");
    agent.subscribe(lane, channel).expect("subscribe");
    for filter in ["", "bad\u{2028}topic"] {
        let error = agent
            .recv_topic(lane, channel, filter)
            .expect_err("an invalid filter is refused");
        assert_eq!(error.code(), "rpc/invalid-argument");
    }
    assert_eq!(
        agent
            .recv_topic(lane, channel, "absent")
            .expect("no message"),
        None
    );
}

/// Guard: the channel byte counter is exposed and exact.
#[test]
fn channel_bytes_are_exact() {
    let (agent, _provider) = agent();
    let lane = agent.create_lane("exact", Budget::default()).expect("lane");
    let channel = agent
        .create_channel("exact", Direction::Both)
        .expect("channel");
    agent.subscribe(lane, channel).expect("subscribe");
    let value = Value::text("payload");
    let size = value.wire_size();
    agent.send(lane, channel, value, &[]).expect("send");
    assert_eq!(agent.channel(channel).expect("channel").queued_bytes, size);
    agent.recv(lane, channel).expect("recv").expect("message");
    assert_eq!(agent.channel(channel).expect("channel").queued_bytes, 0);
}
