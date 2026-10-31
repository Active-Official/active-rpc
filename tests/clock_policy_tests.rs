//! Clock policy (ADR-0022): the virtual clock is the default, wall-clock mode
//! tracks real time, and neither ever moves backwards.

use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::value::{Call, Response, Value};
use active_rpc::{Agent, Budget};

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

    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::Text("ok".into())))
    }
}

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
}

#[test]
fn the_default_clock_is_virtual_and_advances_by_one_round_trip() {
    let agent = Agent::with_secret([0x61; 32]);
    assert!(!agent.uses_wall_clock());
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let lane = agent.create_lane("clock", Budget::default()).expect("lane");
    agent.set_latency(100);
    assert_eq!(agent.now_ms(), 0);
    let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("call");
    agent.run();
    promise.value().expect("value");
    assert_eq!(agent.now_ms(), 100);
    let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("call");
    agent.run();
    promise.value().expect("value");
    assert_eq!(agent.now_ms(), 200);
}

#[test]
fn wall_clock_mode_tracks_the_system_clock() {
    let agent = Agent::with_secret([0x62; 32]);
    let before = wall_ms();
    agent.use_wall_clock(true);
    assert!(agent.uses_wall_clock());
    let observed = agent.now_ms();
    let after = wall_ms();
    assert!(
        observed >= before && observed <= after + 1,
        "observed {observed}, window {before}..{after}"
    );
}

#[test]
fn a_wall_clock_agent_accepts_a_live_capability_and_refuses_an_expired_one() {
    let agent = Agent::with_secret([0x63; 32]);
    agent.use_wall_clock(true);
    let provider = agent.register(Box::new(Echo));
    let lane = agent.create_lane("clock", Budget::default()).expect("lane");

    let live = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]).with_ttl_ms(60_000))
        .expect("live cap");
    let promise = agent.call(lane, &live, "echo", Vec::new()).expect("call");
    agent.run();
    promise.value().expect("value");

    let expired = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]).with_ttl_ms(0))
        .expect("expired cap");
    let error = agent
        .call(lane, &expired, "echo", Vec::new())
        .expect_err("a zero lifetime is already expired");
    assert_eq!(error.code(), "rpc/revoked");
}

#[test]
fn the_clock_never_moves_backwards_when_the_mode_changes() {
    let agent = Agent::with_secret([0x64; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let lane = agent.create_lane("clock", Budget::default()).expect("lane");
    agent.set_latency(100);
    for _ in 0..3 {
        let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("call");
        agent.run();
        promise.value().expect("value");
    }
    assert_eq!(agent.now_ms(), 300);

    // Enabling the wall clock jumps forward to real time.
    agent.use_wall_clock(true);
    let jumped = agent.now_ms();
    assert!(jumped >= 300, "wall clock went backwards: {jumped}");
    assert!(jumped > 1_000_000, "wall clock is not real time: {jumped}");

    // Disabling it keeps the current time; the clock never rewinds.
    agent.use_wall_clock(false);
    assert_eq!(agent.now_ms(), jumped);
    let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("call");
    agent.run();
    promise.value().expect("value");
    assert!(
        agent.now_ms() >= jumped,
        "the virtual clock rewound after the switch"
    );
}

#[test]
fn dispatch_re_checks_the_deadline_under_the_wall_clock() {
    let agent = Agent::with_secret([0x65; 32]);
    agent.use_wall_clock(true);
    let provider = agent.register(Box::new(Echo));
    let lane = agent.create_lane("clock", Budget::default()).expect("lane");
    // A one-millisecond deadline is live when queued but can expire before
    // dispatch; either check refuses it, and neither ever lets it run.
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]).with_ttl_ms(1))
        .expect("cap");
    std::thread::sleep(std::time::Duration::from_millis(5));
    let outcome = agent.call(lane, &cap, "echo", Vec::new());
    match outcome {
        Ok(promise) => {
            agent.run();
            let error = promise.value().expect_err("expired before the provider");
            assert_eq!(error.code(), "rpc/revoked");
        }
        Err(error) => assert_eq!(error.code(), "rpc/revoked"),
    }
}
