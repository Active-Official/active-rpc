//! R-02 dispatch round 5: a batch must not run work the caller already
//! cancelled or answered, cancellations must be on the tape, and every
//! dispatch-time refusal must be counted.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::{Agent, Budget, PromiseHandle};

struct Worker {
    agent: Rc<RefCell<Option<Agent>>>,
    victim: Rc<RefCell<Option<PromiseHandle>>>,
    self_handle: Rc<RefCell<Option<PromiseHandle>>>,
    runs: Rc<Cell<usize>>,
}

impl Provider for Worker {
    fn name(&self) -> &'static str {
        "worker"
    }

    fn methods(&self) -> Vec<String> {
        vec![
            "kill".to_string(),
            "resolve-next".to_string(),
            "self-cancel".to_string(),
            "work".to_string(),
        ]
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, call: &Call) -> active_rpc::Result<Response> {
        let agent = self.agent.borrow();
        let agent = agent.as_ref().expect("agent installed");
        match call.method.as_str() {
            "kill" => {
                if let Some(handle) = self.victim.borrow().as_ref() {
                    agent.cancel(handle).expect("cancel the queued job");
                }
            }
            "resolve-next" => {
                if let Some(handle) = self.victim.borrow().as_ref() {
                    agent
                        .resolve(handle, Value::text("answered"))
                        .expect("resolve");
                }
            }
            "self-cancel" => {
                if let Some(handle) = self.self_handle.borrow().as_ref() {
                    agent.cancel(handle).expect("cancel itself");
                }
                self.runs.set(self.runs.get() + 1);
            }
            _ => {
                self.runs.set(self.runs.get() + 1);
            }
        }
        Ok(Response::Value(Value::text("ok")))
    }
}

fn worker_agent() -> (Agent, active_rpc::CapHandle, Rc<Cell<usize>>) {
    let agent = Agent::with_secret([0x91; 32]);
    let slot: Rc<RefCell<Option<Agent>>> = Rc::new(RefCell::new(None));
    let victim: Rc<RefCell<Option<PromiseHandle>>> = Rc::new(RefCell::new(None));
    let self_handle: Rc<RefCell<Option<PromiseHandle>>> = Rc::new(RefCell::new(None));
    let runs = Rc::new(Cell::new(0usize));
    let provider = agent.register(Box::new(Worker {
        agent: Rc::clone(&slot),
        victim: Rc::clone(&victim),
        self_handle: Rc::clone(&self_handle),
        runs: Rc::clone(&runs),
    }));
    *slot.borrow_mut() = Some(agent.clone());
    let cap = agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["kill", "resolve-next", "self-cancel", "work"]),
        )
        .expect("cap");
    // The provider reads the handles through these cells; the test fills them
    // between queueing and running.
    AGENT_SLOT.with(|slot| *slot.borrow_mut() = Some(agent.clone()));
    VICTIM.with(|cell| *cell.borrow_mut() = Some(Rc::clone(&victim)));
    SELF.with(|cell| *cell.borrow_mut() = Some(Rc::clone(&self_handle)));
    (agent, cap, runs)
}

thread_local! {
    static AGENT_SLOT: RefCell<Option<Agent>> = const { RefCell::new(None) };
    static VICTIM: RefCell<Option<Rc<RefCell<Option<PromiseHandle>>>>> = const { RefCell::new(None) };
    static SELF: RefCell<Option<Rc<RefCell<Option<PromiseHandle>>>>> = const { RefCell::new(None) };
}

#[test]
fn a_batched_job_cancelled_by_an_earlier_call_does_not_run() {
    let (agent, cap, runs) = worker_agent();
    let lane = agent.create_lane("batch", Budget::default()).expect("lane");
    let first = agent.call(lane, &cap, "kill", Vec::new()).expect("first");
    let second = agent.call(lane, &cap, "work", Vec::new()).expect("second");
    VICTIM.with(|cell| {
        cell.borrow()
            .as_ref()
            .unwrap()
            .borrow_mut()
            .replace(second.clone())
    });
    agent.run();
    assert_eq!(
        runs.get(),
        0,
        "the provider ran a job the caller cancelled before it started"
    );
    assert_eq!(
        second.value().expect_err("cancelled").code(),
        "rpc/promise-cancelled"
    );
    first.value().expect("the cancelling call settles");
}

#[test]
fn a_batched_job_answered_by_an_earlier_call_does_not_run() {
    let (agent, cap, runs) = worker_agent();
    let lane = agent.create_lane("batch", Budget::default()).expect("lane");
    let first = agent
        .call(lane, &cap, "resolve-next", Vec::new())
        .expect("first");
    let second = agent.call(lane, &cap, "work", Vec::new()).expect("second");
    VICTIM.with(|cell| {
        cell.borrow()
            .as_ref()
            .unwrap()
            .borrow_mut()
            .replace(second.clone())
    });
    agent.run();
    assert_eq!(
        runs.get(),
        0,
        "the provider ran a job the kernel had already answered out of band"
    );
    assert_eq!(second.value().expect("answered"), Value::text("answered"));
    first.value().expect("the answering call settles");
}

#[test]
fn cancelling_itself_is_on_the_tape() {
    let (agent, cap, runs) = worker_agent();
    agent.enable_receipts(true);
    let lane = agent.create_lane("self", Budget::default()).expect("lane");
    let promise = agent
        .call(lane, &cap, "self-cancel", Vec::new())
        .expect("call");
    SELF.with(|cell| {
        cell.borrow()
            .as_ref()
            .unwrap()
            .borrow_mut()
            .replace(promise.clone())
    });
    agent.run();
    assert_eq!(runs.get(), 1, "the provider ran");
    assert_eq!(
        promise.value().expect_err("cancelled").code(),
        "rpc/promise-cancelled"
    );
    let receipts = agent.receipts();
    assert_eq!(
        receipts.len(),
        1,
        "the executed-then-cancelled call has no receipt"
    );
    assert_eq!(
        receipts[0].decision,
        active_rpc::receipts::Decision::Refused("rpc/promise-cancelled".to_string())
    );
}

/// A pipeline whose producer answers with a path outside the capability's scope
/// is refused at dispatch; the refusal must be counted and traced.
#[test]
fn a_dispatch_time_path_refusal_is_counted() {
    struct Leaker;
    impl Provider for Leaker {
        fn name(&self) -> &'static str {
            "leaker"
        }
        fn methods(&self) -> Vec<String> {
            vec!["leak".to_string(), "echo".to_string()]
        }
        fn mutating(&self, _method: &str) -> bool {
            false
        }
        fn invoke(&mut self, _object: u64, call: &Call) -> active_rpc::Result<Response> {
            if call.method == "leak" {
                Ok(Response::Value(Value::path("secret/x")))
            } else {
                Ok(Response::Value(Value::text("ok")))
            }
        }
    }

    let agent = Agent::with_secret([0x92; 32]);
    let provider = agent.register(Box::new(Leaker));
    let cap = agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["leak", "echo"]).with_path("allowed"),
        )
        .expect("cap");
    let lane = agent.create_lane("pipe", Budget::default()).expect("lane");
    let producer = agent.call(lane, &cap, "leak", Vec::new()).expect("leak");
    let consumer = agent
        .call(lane, &cap, "echo", vec![Arg::Promise(producer.id())])
        .expect("consumer");
    let before = agent.metrics().calls_refused;
    agent.run();
    let error = consumer.value().expect_err("the path is outside the scope");
    assert_eq!(error.code(), "rpc/path-not-granted");
    assert_eq!(
        agent.metrics().calls_refused,
        before + 1,
        "the dispatch refusal was not counted"
    );
    let json = agent.trace_json();
    assert!(
        json.contains("\"event\":\"call.refused\""),
        "the dispatch refusal is not on the tape: {json}"
    );
}

struct Failing {
    agent: Rc<RefCell<Option<Agent>>>,
    own: Rc<RefCell<Option<PromiseHandle>>>,
}

impl Provider for Failing {
    fn name(&self) -> &'static str {
        "failing"
    }

    fn methods(&self) -> Vec<String> {
        vec!["go".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        let agent = self.agent.borrow();
        let agent = agent.as_ref().expect("agent installed");
        if let Some(handle) = self.own.borrow().as_ref() {
            agent.cancel(handle).expect("cancel itself");
        }
        Err(active_rpc::Error::ToolPolicy("refused after cancel"))
    }
}

#[test]
fn a_cancelled_running_job_seals_one_receipt_even_when_it_fails() {
    // Round 6 (#1): the out-of-band flag was set only on the success branch, so
    // a self-cancelling provider that then failed sealed a second receipt and
    // counted a double settlement.
    let agent = Agent::with_secret([0x93; 32]);
    agent.enable_receipts(true);
    let slot: Rc<RefCell<Option<Agent>>> = Rc::new(RefCell::new(None));
    let own: Rc<RefCell<Option<PromiseHandle>>> = Rc::new(RefCell::new(None));
    let provider = agent.register(Box::new(Failing {
        agent: Rc::clone(&slot),
        own: Rc::clone(&own),
    }));
    *slot.borrow_mut() = Some(agent.clone());
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["go"]))
        .expect("cap");
    let lane = agent.create_lane("fail", Budget::default()).expect("lane");
    let promise = agent.call(lane, &cap, "go", Vec::new()).expect("call");
    *own.borrow_mut() = Some(promise.clone());
    agent.run();
    assert_eq!(
        promise.value().expect_err("cancelled").code(),
        "rpc/promise-cancelled"
    );
    assert_eq!(agent.receipts().len(), 1, "one decision, one receipt");
    assert_eq!(
        agent.metrics().promises_double_settled,
        0,
        "the discarded outcome was counted as a double settlement"
    );
}

#[test]
fn cancelling_a_queued_job_is_an_event_and_a_refusal() {
    // Round 6 (#2): the tape ended at `call.queued` and the counter was flat.
    let (agent, cap, _runs) = worker_agent();
    let lane = agent
        .create_lane("cancel", Budget::default())
        .expect("lane");
    let promise = agent.call(lane, &cap, "work", Vec::new()).expect("call");
    let before = agent.metrics().calls_refused;
    agent.cancel(&promise).expect("cancel");
    assert_eq!(agent.metrics().calls_refused, before + 1);
    let json = agent.trace_json();
    assert!(json.contains("\"event\":\"call.refused\""), "{json}");
    assert!(json.contains("\"event\":\"job.completed\""), "{json}");
}

#[test]
fn a_dispatch_budget_refusal_is_a_refused_call() {
    // Round 6 (#3): the budget arms bumped the dimension counter only.
    struct Big;
    impl Provider for Big {
        fn name(&self) -> &'static str {
            "big"
        }
        fn methods(&self) -> Vec<String> {
            vec!["go".to_string()]
        }
        fn mutating(&self, _method: &str) -> bool {
            false
        }
        fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
            Ok(Response::Value(Value::text("x".repeat(4_096))))
        }
    }

    let agent = Agent::with_secret([0x94; 32]);
    let provider = agent.register(Box::new(Big));
    let cap = agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["go"]).with_budget(active_rpc::Budget {
                max_value_size: 128,
                ..active_rpc::Budget::default()
            }),
        )
        .expect("cap");
    let lane = agent
        .create_lane("egress", Budget::default())
        .expect("lane");
    let promise = agent.call(lane, &cap, "go", Vec::new()).expect("call");
    let before = agent.metrics().calls_refused;
    agent.run();
    assert_eq!(
        promise.value().expect_err("too large").code(),
        "rpc/budget-exceeded"
    );
    assert_eq!(agent.metrics().calls_refused, before + 1);
    let json = agent.trace_json();
    assert!(json.contains("\"event\":\"call.refused\""), "{json}");
}

struct TreeCanceller {
    agent: Rc<RefCell<Option<Agent>>>,
    own: Rc<RefCell<Option<PromiseHandle>>>,
    runs: Rc<Cell<usize>>,
}

impl Provider for TreeCanceller {
    fn name(&self) -> &'static str {
        "tree-canceller"
    }

    fn methods(&self) -> Vec<String> {
        vec!["go".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        let agent = self.agent.borrow();
        let agent = agent.as_ref().expect("agent installed");
        if let Some(handle) = self.own.borrow().as_ref() {
            agent.cancel_tree(handle).expect("cancel its own tree");
        }
        self.runs.set(self.runs.get() + 1);
        Ok(Response::Value(Value::text("ok")))
    }
}

#[test]
fn cancelling_a_running_tree_is_on_the_tape() {
    // Round 7 (#1): `cancel_tree` only recorded the settled state for a running
    // target, so executed work left no decision in the receipts.
    let agent = Agent::with_secret([0x95; 32]);
    agent.enable_receipts(true);
    let slot: Rc<RefCell<Option<Agent>>> = Rc::new(RefCell::new(None));
    let own: Rc<RefCell<Option<PromiseHandle>>> = Rc::new(RefCell::new(None));
    let runs = Rc::new(Cell::new(0usize));
    let provider = agent.register(Box::new(TreeCanceller {
        agent: Rc::clone(&slot),
        own: Rc::clone(&own),
        runs: Rc::clone(&runs),
    }));
    *slot.borrow_mut() = Some(agent.clone());
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["go"]))
        .expect("cap");
    let lane = agent.create_lane("tree", Budget::default()).expect("lane");
    let promise = agent.call(lane, &cap, "go", Vec::new()).expect("call");
    *own.borrow_mut() = Some(promise.clone());
    agent.run();
    assert_eq!(runs.get(), 1, "the provider ran");
    assert_eq!(
        promise.value().expect_err("cancelled").code(),
        "rpc/promise-cancelled"
    );
    assert_eq!(
        agent.receipts().len(),
        1,
        "the executed work has no decision"
    );
}

#[test]
fn answering_a_queued_job_completes_it_on_the_tape() {
    // Round 7 (#3): the tape ended at `call.queued`.
    let (agent, cap, runs) = worker_agent();
    let lane = agent
        .create_lane("answer", Budget::default())
        .expect("lane");
    let promise = agent.call(lane, &cap, "work", Vec::new()).expect("call");
    agent
        .resolve(&promise, Value::text("answered"))
        .expect("answer");
    let json = agent.trace_json();
    assert!(json.contains("\"event\":\"job.completed\""), "{json}");
    assert_eq!(runs.get(), 0, "the provider did not run");
}

#[test]
fn resolving_a_cancelled_job_says_cancelled() {
    // Round 7 (#4): the record reported "already resolved", which invites a
    // retry of a call the caller cancelled.
    let (agent, cap, _runs) = worker_agent();
    let lane = agent
        .create_lane("cancelled", Budget::default())
        .expect("lane");
    let promise = agent.call(lane, &cap, "work", Vec::new()).expect("call");
    agent.cancel(&promise).expect("cancel");
    let error = agent
        .resolve(&promise, Value::text("late"))
        .expect_err("a cancelled promise cannot be answered");
    assert_eq!(error.code(), "rpc/promise-cancelled");
}
