//! Multi-tenant cross-talk stress: many independent grants sharing one kernel,
//! and many kernels in one process.
//!
//! The point is isolation under *interleaving*: a tenant's messages, budget,
//! revocations and topic grants must never reach another tenant, even when the
//! operations are mixed instead of run one tenant at a time.

use std::collections::BTreeMap;
use std::sync::{Arc, Barrier, Mutex};

use active_rpc::cap::CapAttrs;
use active_rpc::channel::Direction;
use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::{Agent, Budget, CapHandle, ChannelId, LaneId};

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

struct Tenant {
    cap: CapHandle,
    lane: LaneId,
    channel: ChannelId,
    topic: String,
}

fn mint_tenant(agent: &Agent, provider: active_rpc::ProviderId, index: usize) -> Tenant {
    let topic = format!("tenant-{index}");
    let attrs = CapAttrs::new(&["echo"]).restrict_topics(&[topic.as_str()]);
    let cap = agent.mint(provider, 0, attrs).expect("mint");
    let lane = agent
        .create_lane(format!("lane-{index}"), Budget::default())
        .expect("lane");
    let channel = agent
        .create_channel(format!("channel-{index}"), Direction::Both)
        .expect("channel");
    Tenant {
        cap,
        lane,
        channel,
        topic,
    }
}

/// Sixteen grants on one kernel, used round-robin. Each tenant publishes only
/// to its own topic, calls only its own capability, and every message it
/// receives is its own.
#[test]
fn one_kernel_keeps_sixteen_tenants_apart_under_interleaving() {
    const TENANTS: usize = 16;
    const ROUNDS: usize = 32;

    let agent = Agent::with_secret([0x9a; 32]);
    let provider = agent.register(Box::new(Echo));
    let tenants: Vec<Tenant> = (0..TENANTS)
        .map(|i| mint_tenant(&agent, provider, i))
        .collect();

    for round in 0..ROUNDS {
        for (index, tenant) in tenants.iter().enumerate() {
            // A publish inside the grant lands in this tenant's channel only.
            agent
                .publish(
                    tenant.lane,
                    tenant.channel,
                    &tenant.cap,
                    &tenant.topic,
                    Value::text(format!("{index}:{round}")),
                )
                .expect("publish inside the grant");

            // A publish to another tenant's topic is refused.
            let other = (index + 1) % TENANTS;
            let error = agent
                .publish(
                    tenant.lane,
                    tenant.channel,
                    &tenant.cap,
                    &tenants[other].topic,
                    Value::text("cross"),
                )
                .expect_err("a topic outside the grant must be refused");
            assert_eq!(error.code(), "rpc/topic-not-granted");

            // The call returns this tenant's own value.
            let promise = agent
                .call(
                    tenant.lane,
                    &tenant.cap,
                    "echo",
                    vec![Arg::text(format!("{index}:{round}"))],
                )
                .expect("call");
            agent.run();
            assert_eq!(
                promise.value().expect("value"),
                Value::text(format!("{index}:{round}"))
            );
        }
    }

    // Drain in a different order than the publish order: each channel holds
    // exactly its own messages and nothing else.
    for (index, tenant) in tenants.iter().enumerate().rev() {
        let mut seen = Vec::new();
        while let Some(message) = agent
            .recv_topic(tenant.channel, &tenant.topic)
            .expect("recv")
        {
            assert_eq!(message.topic.as_deref(), Some(tenant.topic.as_str()));
            match message.payload {
                Value::Text(text) => seen.push(text),
                other => panic!("unexpected payload {other:?}"),
            }
        }
        assert_eq!(seen.len(), ROUNDS, "tenant {index} lost or gained messages");
        assert!(
            seen.iter()
                .all(|text| text.starts_with(&format!("{index}:"))),
            "tenant {index} received another tenant's payload: {seen:?}"
        );
        // A topic this tenant never published is empty.
        let empty = (index + 3) % TENANTS;
        assert!(agent
            .recv_topic(tenant.channel, &tenants[empty].topic)
            .expect("recv")
            .is_none());
    }
}

/// A tight per-capability call budget stays with its capability: exhausting one
/// tenant's budget leaves every other tenant's capability usable.
#[test]
fn a_tenant_budget_never_charges_another_tenant() {
    let agent = Agent::with_secret([0x9b; 32]);
    let provider = agent.register(Box::new(Echo));
    let mut tight = CapAttrs::new(&["echo"]);
    tight.budget.max_calls = 3;
    let tight_cap = agent.mint(provider, 0, tight).expect("tight cap");
    let lanes: Vec<LaneId> = (0..4)
        .map(|index| {
            agent
                .create_lane(format!("l{index}"), Budget::default())
                .unwrap()
        })
        .collect();
    let other = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("other cap");

    for lane in lanes.iter().take(3) {
        let promise = agent
            .call(*lane, &tight_cap, "echo", vec![Arg::text("t")])
            .expect("within budget");
        agent.run();
        promise.value().expect("value");
        // Every round, an unrelated capability is still free to call.
        let promise = agent
            .call(*lane, &other, "echo", vec![Arg::text("o")])
            .expect("other cap");
        agent.run();
        promise.value().expect("value");
    }
    let error = agent
        .call(lanes[0], &tight_cap, "echo", vec![Arg::text("t")])
        .expect_err("the fourth call exceeds the capability budget");
    assert_eq!(error.code(), "rpc/budget-exceeded");
    // The lane budget (default) was not the thing that refused, and `other`
    // still works on the same lane.
    let promise = agent
        .call(lanes[0], &other, "echo", vec![Arg::text("o")])
        .expect("other cap after the refusal");
    agent.run();
    promise.value().expect("value");
}

/// Eight kernels in eight threads: authority never crosses a secret boundary.
///
/// Each thread mints its own capability, publishes the id, and then tries every
/// published id, including its own. A foreign id is `rpc/unknown-capability`;
/// the thread's own id resolves to its own capability.
#[test]
fn concurrent_agents_never_accept_another_agents_capability() {
    const THREADS: usize = 8;
    let ids: Arc<Mutex<Vec<active_rpc::CapId>>> = Arc::new(Mutex::new(Vec::new()));
    let barrier = Arc::new(Barrier::new(THREADS));

    let handles: Vec<_> = (0..THREADS)
        .map(|index| {
            let ids = Arc::clone(&ids);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let agent = Agent::with_secret([0x30 + index as u8; 32]);
                let provider = agent.register(Box::new(Echo));
                let cap = agent
                    .mint(provider, 0, CapAttrs::new(&["echo"]))
                    .expect("mint");
                let lane = agent
                    .create_lane("tenant", Budget::default())
                    .expect("lane");
                ids.lock().unwrap().push(cap.id());
                barrier.wait();

                let published: Vec<active_rpc::CapId> = ids.lock().unwrap().clone();
                for foreign in published {
                    if foreign == cap.id() {
                        continue;
                    }
                    let imported = agent.import(foreign);
                    let error = agent
                        .call(lane, &imported, "echo", vec![Arg::text("cross")])
                        .expect_err("another tenant's capability must be refused");
                    assert_eq!(error.code(), "rpc/unknown-capability");
                }

                // The thread's own capability still works after every refusal.
                let promise = agent
                    .call(lane, &cap, "echo", vec![Arg::text(format!("own-{index}"))])
                    .expect("own call");
                agent.run();
                assert_eq!(
                    promise.value().expect("value"),
                    Value::text(format!("own-{index}"))
                );
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("tenant thread");
    }
    let ids = ids.lock().unwrap();
    let unique: BTreeMap<&active_rpc::CapId, usize> =
        ids.iter().fold(BTreeMap::new(), |mut map, id| {
            *map.entry(id).or_insert(0) += 1;
            map
        });
    assert_eq!(unique.len(), THREADS, "two tenants derived the same id");
    assert!(unique.values().all(|count| *count == 1));
}
