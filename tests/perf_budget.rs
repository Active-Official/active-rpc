//! Performance and availability budgets for Active RPC.
//!
//! Generous ceilings catch a super-linear regression or an unbounded
//! allocation; they are not a machine benchmark. Numbers live in
//! `docs/spec/performance.md`.

use std::time::{Duration, Instant};

use active_rpc::error::Result;
use active_rpc::value::Call;
use active_rpc::wire::{Envelope, WireLimits};
use active_rpc::{Agent, Arg, Budget, CapAttrs, Provider, ProviderId, Response, Value};

struct Echo;

impl Provider for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }
    fn methods(&self) -> Vec<String> {
        vec!["ping".into()]
    }
    fn mutating(&self, _method: &str) -> bool {
        false
    }
    fn invoke(&mut self, _object: u64, _call: &Call) -> Result<Response> {
        Ok(Response::Value(Value::text("pong")))
    }
}

fn agent_with_budget(
    budget: Budget,
) -> (Agent, ProviderId, active_rpc::CapHandle, active_rpc::LaneId) {
    let agent = Agent::with_secret([7u8; 32]);
    let provider = agent.register(Box::new(Echo));
    let lane = agent.create_lane("perf", budget).expect("lane");
    let mut attrs = CapAttrs::new(&["ping"]);
    attrs.budget = budget;
    let cap = agent.mint(provider, 0, attrs).expect("cap");
    (agent, provider, cap, lane)
}

fn agent() -> (Agent, ProviderId, active_rpc::CapHandle, active_rpc::LaneId) {
    agent_with_budget(Budget::default())
}

#[test]
fn envelope_decode_is_linear() {
    let small = Envelope::request(
        1,
        "stats",
        (0..100).map(|i| Arg::Value(Value::Int(i))).collect(),
    )
    .encode()
    .expect("small");
    let large = Envelope::request(
        1,
        "stats",
        (0..2_000).map(|i| Arg::Value(Value::Int(i))).collect(),
    )
    .encode()
    .expect("large");
    let measure = |bytes: &[u8], runs: u32| {
        let start = Instant::now();
        for _ in 0..runs {
            let envelope = Envelope::decode(bytes).expect("decode");
            assert!(envelope.args.len() <= WireLimits::default().max_args as usize);
        }
        start.elapsed() / runs
    };
    let t_small = measure(&small, 20);
    let t_large = measure(&large, 10);
    let budget = t_small * 60 + Duration::from_millis(50);
    assert!(
        t_large <= budget,
        "envelope decode scaled worse than linear: 100={t_small:?} 2000={t_large:?}"
    );
}

#[test]
fn in_process_call_throughput_is_bounded() {
    let (agent, _provider, cap, lane) = agent();
    let start = Instant::now();
    for _ in 0..5_000 {
        let promise = agent.call(lane, &cap, "ping", vec![]).expect("call");
        assert_eq!(promise.value().expect("value"), Value::text("pong"));
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(15),
        "5000 in-process calls took {elapsed:?}"
    );
}

#[test]
fn shared_memory_frames_are_bounded() {
    use active_rpc::transport::shm::SharedSegment;
    let segment = SharedSegment::new(4096);
    let frame = vec![0x5a; 256];
    let start = Instant::now();
    for _ in 0..10_000 {
        segment.write(&frame).expect("write");
        assert_eq!(segment.read().expect("read").expect("frame"), frame);
    }
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "10k shared-memory round trips took {:?}",
        start.elapsed()
    );
}

#[cfg(target_os = "linux")]
fn rss_kib() -> u64 {
    let statm = std::fs::read_to_string("/proc/self/statm").expect("statm");
    let pages: u64 = statm.split_whitespace().nth(1).unwrap().parse().unwrap();
    pages * 4
}

#[cfg(target_os = "linux")]
#[test]
fn repeated_calls_do_not_grow_rss() {
    // The default budget allows 10k calls; this test deliberately exceeds it
    // to measure per-call growth, so widen the ceiling for the test only.
    let budget = Budget {
        max_calls: 100_000,
        ..Budget::default()
    };
    let (agent, _provider, cap, lane) = agent_with_budget(budget);
    for _ in 0..200 {
        let promise = agent.call(lane, &cap, "ping", vec![]).expect("warmup");
        let _ = promise.value();
    }
    let before = rss_kib();
    for _ in 0..20_000 {
        let promise = agent.call(lane, &cap, "ping", vec![]).expect("call");
        let _ = promise.value();
    }
    let after = rss_kib();
    assert!(
        after < before + 65_536,
        "RSS grew from {before} KiB to {after} KiB over 20k calls"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn lane_and_channel_churn_does_not_leak_descriptors_or_threads() {
    fn descriptors() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .expect("fd table")
            .count()
    }
    fn threads() -> usize {
        let status = std::fs::read_to_string("/proc/self/status").expect("status");
        status
            .lines()
            .find_map(|line| line.strip_prefix("Threads:"))
            .expect("threads")
            .trim()
            .parse()
            .expect("thread count")
    }

    let agent = Agent::with_secret([9u8; 32]);
    let fds_before = descriptors();
    let threads_before = threads();
    for index in 0..2_000 {
        let lane = agent
            .create_lane(format!("churn-{index}"), Budget::default())
            .expect("lane");
        agent.destroy_lane(lane).expect("destroy");
        let channel = agent
            .create_channel(format!("churn-{index}"), active_rpc::Direction::Both)
            .expect("channel");
        agent.destroy_channel(channel).expect("destroy channel");
    }
    assert!(
        descriptors() <= fds_before,
        "descriptor table grew from {fds_before} to {}",
        descriptors()
    );
    assert!(
        threads() <= threads_before,
        "thread count grew from {threads_before} to {}",
        threads()
    );
}
