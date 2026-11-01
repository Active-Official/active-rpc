//! THROWAWAY probes for the R-04 audit (part 2). Delete after use.

use std::cell::Cell;
use std::rc::Rc;

use active_rpc::budget::Budget;
use active_rpc::cap::CapAttrs;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::{Agent, Provider};

struct Echo;

impl Provider for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }
    fn methods(&self) -> Vec<String> {
        vec!["echo".into()]
    }
    fn invoke(&mut self, _object: u64, call: &Call) -> active_rpc::Result<Response> {
        let value = call
            .args
            .iter()
            .find_map(|arg| match arg {
                Arg::Value(value) => Some(value.clone()),
                _ => None,
            })
            .unwrap_or(Value::Null);
        Ok(Response::Value(value))
    }
}

fn setup() -> (Agent, active_rpc::CapHandle, active_rpc::LaneId) {
    let agent = Agent::with_secret([0x77; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let lane = agent.create_lane("l", Budget::default()).expect("lane");
    (agent, cap, lane)
}

struct Count(Rc<Cell<usize>>);

impl Provider for Count {
    fn name(&self) -> &'static str {
        "count"
    }
    fn methods(&self) -> Vec<String> {
        vec!["m".into()]
    }
    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        self.0.set(self.0.get() + 1);
        Ok(Response::Value(Value::text("ran")))
    }
}

#[test]
fn probe_resolve_does_not_stop_the_job() {
    let agent = Agent::with_secret([0x76; 32]);
    let hits = Rc::new(Cell::new(0));
    let provider = agent.register(Box::new(Count(hits.clone())));
    let cap = agent.mint(provider, 0, CapAttrs::new(&["m"])).unwrap();
    let lane = agent.create_lane("r", Budget::default()).unwrap();
    let promise = agent.call(lane, &cap, "m", vec![]).unwrap();
    agent
        .resolve(&promise, Value::text("out-of-band"))
        .unwrap();
    agent.run();
    println!(
        "PROBE after resolve: provider hits={} value={:?}",
        hits.get(),
        promise.peek().map(|v| format!("{v:?}"))
    );
    println!(
        "PROBE double_settled={}",
        agent.metrics().promises_double_settled
    );
}

#[test]
fn probe_handle_refcount_desync() {
    let (agent, cap, lane) = setup();
    let first = agent
        .call(lane, &cap, "echo", vec![Arg::text("keep-me")])
        .unwrap();
    {
        let borrowed = agent.cell().borrow_mut();
        let cloned = first.clone();
        drop(cloned);
        drop(borrowed);
    }
    for _ in 0..1_500 {
        agent
            .call(lane, &cap, "echo", vec![Arg::text("x")])
            .unwrap()
            .value()
            .unwrap();
    }
    println!(
        "PROBE live handle after trim: {:?}",
        first.value().map_err(|e| e.code())
    );
    println!(
        "PROBE still known = {}",
        active_rpc::kernel::promise_state(&agent, first.id()).is_some()
    );
}
