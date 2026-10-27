//! Concurrency tests: many lanes, many channels, several tools, and two agents
//! over a real socket.
//!
//! The kernel is a deterministic state machine, so "concurrent" means
//! *interleaved*: several lanes have work in flight at the same time, and the
//! scheduler must make progress on all of them without mixing their budgets,
//! their channels or their providers.

use std::sync::{Arc, Mutex};

use active_rpc::cap::CapAttrs;
use active_rpc::channel::Direction;
use active_rpc::domain::ModuleProvider;
use active_rpc::kernel::{Event, Provider};
use active_rpc::transport::{serve_connection, TcpTransport, Transport};
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::wire::{Envelope, Kind};
use active_rpc::{Agent, Budget};

const SOURCE: &str = "[app]\nport = 8080\nname = \"concurrency\"\n";

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

fn module_agent() -> (Agent, active_rpc::CapHandle) {
    let mut provider = ModuleProvider::new();
    let object =
        provider.install(active_rpc::domain::module_from_source(SOURCE, "c.active").unwrap());
    let agent = Agent::with_secret([31u8; 32]);
    let provider_id = agent.register(Box::new(provider));
    let cap = agent
        .mint(
            provider_id,
            object,
            CapAttrs::new(active_rpc::MODULE_METHODS),
        )
        .unwrap();
    (agent, cap)
}

#[test]
fn lanes_interleave_in_one_batch() {
    let (agent, cap) = module_agent();
    let mut lanes = Vec::new();
    for index in 0..4 {
        lanes.push(
            agent
                .create_lane(format!("lane-{index}"), Budget::default())
                .unwrap(),
        );
    }
    for lane in &lanes {
        agent.call(*lane, &cap, "stats", vec![]).unwrap();
    }
    let before = agent.round_trips();
    agent.run();
    let round_trips = agent.round_trips() - before;
    assert_eq!(round_trips, 1, "one batch serves every lane's queued job");

    let events = agent.events();
    let batch = events
        .iter()
        .find_map(|event| match event {
            Event::BatchDispatched { jobs, lanes, .. } => Some((*jobs, lanes.clone())),
            _ => None,
        })
        .expect("a batch was dispatched");
    assert_eq!(batch.0, 4, "all four jobs dispatched together");
    assert_eq!(batch.1.len(), 4, "four distinct lanes in the batch");
    for lane in lanes {
        assert_eq!(agent.lane(lane).unwrap().completed, 1);
    }
}

#[test]
fn lane_budgets_do_not_leak_between_lanes() {
    let (agent, cap) = module_agent();
    let tight = agent.create_lane("tight", Budget::calls(1)).unwrap();
    let roomy = agent.create_lane("roomy", Budget::default()).unwrap();
    let first = agent.call(tight, &cap, "stats", vec![]).unwrap();
    assert!(
        first.value().is_ok(),
        "the tight lane's single call completes"
    );
    let error = agent
        .call(tight, &cap, "stats", vec![])
        .expect_err("tight lane exhausted");
    assert_eq!(error.code(), "rpc/budget-exceeded");
    // The roomy lane runs ten calls without touching the tight lane's budget.
    for _ in 0..10 {
        let promise = agent.call(roomy, &cap, "stats", vec![]).unwrap();
        assert!(promise.value().is_ok());
    }
    assert_eq!(agent.lane(tight).unwrap().completed, 1);
    assert_eq!(agent.lane(roomy).unwrap().completed, 10);
}

#[test]
fn channels_do_not_cross_talk() {
    let agent = Agent::with_secret([32u8; 32]);
    let lane = agent.create_lane("main", Budget::default()).unwrap();
    let left = agent.create_channel("left", Direction::Both).unwrap();
    let right = agent.create_channel("right", Direction::Both).unwrap();
    for index in 0..5 {
        agent.send(lane, left, Value::Int(index), &[]).unwrap();
        agent
            .send(lane, right, Value::Int(100 + index), &[])
            .unwrap();
    }
    for index in 0..5 {
        let message = agent.recv(left).unwrap().expect("left message");
        assert_eq!(message.payload, Value::Int(index));
        assert_eq!(message.sequence, index as u64);
        let message = agent.recv(right).unwrap().expect("right message");
        assert_eq!(message.payload, Value::Int(100 + index));
    }
    assert!(agent.recv(left).unwrap().is_none());
    assert!(agent.recv(right).unwrap().is_none());
}

#[test]
fn concurrent_tool_calls_across_providers() {
    let agent = Agent::with_secret([33u8; 32]);
    let echo_one = agent.register(Box::new(Echo));
    let echo_two = agent.register(Box::new(Echo));
    let mut provider = ModuleProvider::new();
    let object = provider.install(active_rpc::domain::module_from_source(SOURCE, "d").unwrap());
    let modules = agent.register(Box::new(provider));

    let cap_a = agent.mint(echo_one, 0, CapAttrs::new(&["echo"])).unwrap();
    let cap_b = agent.mint(echo_two, 0, CapAttrs::new(&["echo"])).unwrap();
    let cap_m = agent
        .mint(modules, object, CapAttrs::new(active_rpc::MODULE_METHODS))
        .unwrap();
    let lane_a = agent.create_lane("a", Budget::default()).unwrap();
    let lane_b = agent.create_lane("b", Budget::default()).unwrap();
    let lane_m = agent.create_lane("m", Budget::default()).unwrap();

    let first = agent
        .call(lane_a, &cap_a, "echo", vec![Arg::text("a")])
        .unwrap();
    let second = agent
        .call(lane_b, &cap_b, "echo", vec![Arg::text("b")])
        .unwrap();
    let third = agent.call(lane_m, &cap_m, "stats", vec![]).unwrap();

    assert_eq!(first.value().unwrap(), Value::text("a"));
    assert_eq!(second.value().unwrap(), Value::text("b"));
    assert!(matches!(third.value().unwrap(), Value::Map(_)));

    let batches = agent
        .events()
        .iter()
        .filter(|event| matches!(event, Event::BatchDispatched { .. }))
        .count();
    assert_eq!(batches, 3, "one batch per provider, no cross-talk");
    assert_eq!(agent.lane(lane_a).unwrap().completed, 1);
    assert_eq!(agent.lane(lane_b).unwrap().completed, 1);
    assert_eq!(agent.lane(lane_m).unwrap().completed, 1);
}

#[test]
fn two_agents_over_tcp_do_not_cross_talk() {
    let (listener, address) = active_rpc::transport::bind_loopback().expect("bind");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_server = Arc::clone(&seen);

    let server = std::thread::spawn(move || {
        let mut served = 0u64;
        for _ in 0..2 {
            let (stream, _) = listener.accept().expect("accept");
            let transport = TcpTransport::new(stream).expect("wrap");
            let seen = Arc::clone(&seen_server);
            served += serve_connection(transport, move |envelope| {
                let echo = envelope.first_value().cloned().unwrap_or(Value::Null);
                seen.lock().unwrap().push(echo.clone());
                Envelope::response(envelope.request_id, echo)
            })
            .expect("serve");
        }
        served
    });

    // Two client threads, each with its own agent and its own stream.
    let mut clients = Vec::new();
    for index in 0..2 {
        let address = address.clone();
        clients.push(std::thread::spawn(move || {
            let agent = Agent::with_secret([40 + index as u8; 32]);
            let provider_id = agent.register(Box::new(Echo));
            let cap = agent
                .mint(provider_id, 0, CapAttrs::new(&["echo"]))
                .unwrap();
            let lane = agent.create_lane("main", Budget::default()).unwrap();
            let mut transport = TcpTransport::connect(&address).expect("connect");
            for round in 0..5 {
                let value = format!("agent-{index}-round-{round}");
                let local = agent
                    .call(lane, &cap, "echo", vec![Arg::text(value.clone())])
                    .unwrap();
                assert_eq!(local.value().unwrap(), Value::text(value.clone()));
                transport
                    .send(&Envelope::request(
                        round,
                        "echo",
                        vec![Arg::text(value.clone())],
                    ))
                    .expect("send");
                let response = transport.recv().expect("recv").expect("response");
                assert_eq!(response.kind, Kind::Response);
                assert_eq!(response.first_value(), Some(&Value::text(value)));
            }
        }));
    }
    for client in clients {
        client.join().expect("client thread");
    }
    let served = server.join().expect("server thread");
    assert_eq!(served, 10);
    // The server saw every message exactly once, interleaved across agents.
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 10);
}
