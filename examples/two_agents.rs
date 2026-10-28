//! Two agents, an attenuated capability and a channel.
//!
//! Run with `cargo run --example two_agents`.

use active_rpc::error::Result;
use active_rpc::value::Call;
use active_rpc::{Agent, Arg, Budget, CapAttrs, Direction, Provider, Response, Value};

struct Echo;

impl Provider for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }
    fn methods(&self) -> Vec<String> {
        vec!["echo".into()]
    }
    fn mutating(&self, _method: &str) -> bool {
        false
    }
    fn invoke(&mut self, _object: u64, _call: &Call) -> Result<Response> {
        Ok(Response::Value(Value::text("pong")))
    }
}

fn main() -> Result<()> {
    let agent = Agent::with_secret([7u8; 32]);
    let provider = agent.register(Box::new(Echo));
    let lane = agent.create_lane("demo", Budget::default())?;

    // The root capability can call once. The attenuated one cannot widen it.
    let root = agent.mint(provider, 0, CapAttrs::new(&["echo"]))?;
    let leaf = agent.attenuate(
        &root,
        CapAttrs::new(&["echo"]).with_budget(Budget::calls(1)),
    )?;
    let attrs = agent.cap_attrs(&leaf)?;
    assert_eq!(attrs.budget.max_calls, 1);

    let promise = agent.call(lane, &leaf, "echo", vec![Arg::text("hello")])?;
    let value = promise.value()?;
    assert_eq!(value, Value::text("pong"));
    println!("call returned {value:?}");

    // A channel carries a value and a capability id; the sender keeps its handle.
    let channel = agent.create_channel("chat", Direction::Both)?;
    agent.subscribe(lane, channel)?;
    agent.send(
        lane,
        channel,
        Value::text("hello, peer"),
        std::slice::from_ref(&leaf),
    )?;
    let message = agent.recv(channel)?.expect("message");
    println!(
        "channel message payload={:?} caps={}",
        message.payload,
        message.caps.len()
    );
    Ok(())
}
