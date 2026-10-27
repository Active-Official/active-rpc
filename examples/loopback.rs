//! Loopback demo: a capability, a lane, two calls and a drop notification.
//!
//! Run with `cargo run --example loopback`. It builds a tiny host provider,
//! mints one capability into a lane, asks it for statistics and for the
//! dependency explanation of a path, then drops the capability so the provider
//! can observe the release. A method the capability does not grant is refused
//! before it reaches the provider.

use active_rpc::domain::{module_from_source, ModuleProvider};
use active_rpc::{Agent, Arg, Budget, CapAttrs, Value};

fn main() -> Result<(), active_rpc::Error> {
    // A provider that owns a module and serves the domain methods over it.
    let mut provider = ModuleProvider::new();
    let object = provider.install(module_from_source(
        "port = 8080\nname = \"loopback\"\n",
        "loopback.active",
    )?);
    let agent = Agent::new();
    let provider_id = agent.register(Box::new(provider));

    // One capability, attenuated to the methods this demo needs.
    let cap = agent.mint(provider_id, object, CapAttrs::new(&["stats", "why"]))?;
    let lane = agent.create_lane("demo", Budget::default())?;

    let stats = agent.call(lane, &cap, "stats", vec![])?;
    println!("stats: {:?}", stats.value()?);

    let why = agent.call(
        lane,
        &cap,
        "why",
        vec![Arg::Value(Value::Path("port".to_string()))],
    )?;
    println!("why: {:?}", why.value()?);

    // Dropping the last handle notifies the provider.
    drop(cap);
    println!("drop notifications: {:?}", agent.take_drops(provider_id));

    // A method the capability does not grant fails closed.
    let narrow = agent.mint(provider_id, object, CapAttrs::new(&["stats"]))?;
    match agent.call(lane, &narrow, "why", vec![Arg::Value(Value::Null)]) {
        Ok(_) => println!("unexpected: the method should be denied"),
        Err(error) => println!("denied as expected: {error}"),
    }
    Ok(())
}
