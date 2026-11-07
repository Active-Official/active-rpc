//! R-17 round 3: the channel byte ceilings charge the message record, and the
//! receive path is the only one that hides a channel from a lane.
//!
//! `queued_size` used to charge payload bytes, transferred ids and the topic
//! name only. A one-byte message is a 96-byte record, so the "256 MiB" kernel
//! ceiling could hold roughly a hundred times that in records (L-1). The host
//! that holds `&Agent` also sees a channel's existence and counts regardless of
//! subscription, which is what the ADRs now say (L-3).

use active_rpc::cap::CapAttrs;
use active_rpc::channel::{
    Channel, ChannelId, Direction, Message, MAX_QUEUED_BYTES, MAX_QUEUED_PER_CHANNEL,
    MESSAGE_OVERHEAD,
};
use active_rpc::kernel::{Provider, MAX_CHANNELS, MAX_QUEUED_CHANNEL_BYTES};
use active_rpc::lane::LaneId;
use active_rpc::value::{Call, Response, Value};
use active_rpc::{Agent, Budget};

struct Sink;

impl Provider for Sink {
    fn name(&self) -> &'static str {
        "sink"
    }
    fn methods(&self) -> Vec<String> {
        vec!["noop".to_string()]
    }
    fn mutating(&self, _method: &str) -> bool {
        false
    }
    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::text("ok")))
    }
}

#[test]
fn a_queued_message_is_charged_its_record() {
    assert_eq!(
        MESSAGE_OVERHEAD as usize,
        std::mem::size_of::<Message>(),
        "the per-message charge must be the record the queue stores"
    );
    assert!(
        Channel::message_bytes(&Value::Null, &[], None) >= MESSAGE_OVERHEAD,
        "an empty message still occupies one record"
    );

    let mut channel = Channel::new(ChannelId(1), "bytes", Direction::Both);
    channel
        .send_sequence(LaneId(1), Value::text("x"), Vec::new())
        .expect("send");
    let queued = channel.peek().expect("queued");
    assert_eq!(
        channel.queued_bytes(),
        Channel::message_bytes(&queued.payload, &queued.caps, queued.topic.as_deref()),
        "the counter and the per-message charge must agree exactly"
    );
    assert!(
        channel.queued_bytes() >= MESSAGE_OVERHEAD,
        "a one-byte message must pay for the record that holds it"
    );
}

#[test]
fn the_kernel_byte_ceiling_binds_before_the_structural_worst_case() {
    let worst_case = MAX_CHANNELS as u64 * MAX_QUEUED_PER_CHANNEL as u64 * MESSAGE_OVERHEAD;
    assert!(
        MAX_QUEUED_CHANNEL_BYTES < worst_case,
        "the global channel ceiling ({MAX_QUEUED_CHANNEL_BYTES} bytes) must bind \
         before {worst_case} record bytes"
    );
}

/// A record's charge is its memory, not its wire image: a null costs one wire
/// byte and 32 bytes inline, so a null-heavy message must pay the difference
/// (R-17 round 6, N-1).
#[test]
fn a_null_heavy_record_is_charged_the_memory_it_holds() {
    let value = Value::List(
        (0..100)
            .map(|_| Value::List(vec![Value::Null; 1_000]))
            .collect(),
    );
    let nodes = 100u64 * 1_000 + 100 + 1;
    let charged = Channel::message_bytes(&value, &[], None);
    assert!(
        charged >= nodes.saturating_mul(std::mem::size_of::<Value>() as u64),
        "the record's inline values are not charged: {charged} for {nodes} nodes"
    );

    // A record whose wire image fits a channel but whose memory does not is
    // refused before anything is queued.
    let agent = Agent::with_secret([0x56; 32]);
    let channel = agent
        .create_channel("nulls", Direction::Both)
        .expect("channel");
    let lane = agent
        .create_lane(
            "nulls",
            Budget {
                max_value_size: u64::MAX,
                max_bytes: u64::MAX,
                ..Budget::default()
            },
        )
        .expect("lane");
    agent.subscribe(lane, channel).expect("subscribe");
    let heavy = Value::List(
        (0..21)
            .map(|_| Value::List(vec![Value::Null; 100_000]))
            .collect(),
    );
    assert!(
        heavy.wire_size() < MAX_QUEUED_BYTES,
        "the wire image fits, the memory does not"
    );
    let error = agent
        .send(lane, channel, heavy, &[])
        .expect_err("the record's memory exceeds the channel ceiling");
    assert_eq!(error.code(), "rpc/backpressure", "{error}");
    assert_eq!(agent.queued_channel_bytes(), 0, "nothing was queued");
}

/// A record is charged what it pins, not what the wire would carry: a text
/// with spare capacity and a map's entry overhead are both part of the cost
/// (R-17 round 7, F-1).
#[test]
fn a_message_is_charged_the_capacity_it_pins() {
    let mut text = String::with_capacity(1 << 20);
    text.push('x');
    let value = Value::Text(text);
    assert_eq!(value.wire_size(), 6, "the wire image is one small string");
    let charged = Channel::message_bytes(&value, &[], None);
    assert!(
        charged >= (1 << 20),
        "a megabyte of spare capacity was charged as {charged} bytes"
    );

    let map = Value::Map(
        (0..11)
            .map(|index| (format!("key{index}"), Value::Int(index)))
            .collect(),
    );
    let charged = Channel::message_bytes(&map, &[], None);
    let per_entry = std::mem::size_of::<Value>() + std::mem::size_of::<String>();
    assert!(
        charged >= 11 * per_entry as u64,
        "a map's keys and nodes are undercharged: {charged}"
    );
}

/// The kernel-wide counter adds and subtracts the same quantity, so a send,
/// a receive and a destroy each close it exactly (R-17 round 4, #1).
#[test]
fn the_kernel_counter_closes_on_send_recv_and_destroy() {
    let agent = Agent::with_secret([0x52; 32]);
    let channel = agent
        .create_channel("counter", Direction::Both)
        .expect("channel");
    let lane = agent
        .create_lane("counter", Budget::default())
        .expect("lane");
    agent.subscribe(lane, channel).expect("subscribe");

    let value = Value::text("x");
    let stored = Channel::message_bytes(&value, &[], None);
    agent.send(lane, channel, value.clone(), &[]).expect("send");
    assert_eq!(
        agent.queued_channel_bytes(),
        stored,
        "the kernel counter charges the record, like the channel does"
    );
    assert_eq!(
        agent.queued_channel_bytes(),
        agent.channel(channel).expect("channel").queued_bytes,
        "the two counters agree"
    );

    agent.recv(lane, channel).expect("recv").expect("message");
    assert_eq!(
        agent.queued_channel_bytes(),
        0,
        "a receive releases exactly what the send charged"
    );

    // The publish path charges the topic with the record, and destroy releases
    // the backlog.
    let provider = agent.register(Box::new(Sink));
    let cap = agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["noop"])
                .allow_publish()
                .restrict_topics(&["t"]),
        )
        .expect("cap");
    agent
        .publish(lane, channel, &cap, "t", Value::text("y"))
        .expect("publish");
    let published = agent.channel(channel).expect("channel").queued_bytes;
    assert_eq!(agent.queued_channel_bytes(), published);
    assert!(published >= MESSAGE_OVERHEAD);
    agent.destroy_channel(channel).expect("destroy");
    assert_eq!(
        agent.queued_channel_bytes(),
        0,
        "a destroy releases exactly the backlog it removed"
    );
}

#[test]
fn the_host_sees_a_channel_a_lane_may_not_read() {
    let agent = Agent::with_secret([0x51; 32]);
    let channel = agent
        .create_channel("hidden", Direction::Both)
        .expect("channel");
    let outsider = agent
        .create_lane("outsider", Budget::default())
        .expect("lane");
    let writer = agent
        .create_lane("writer", Budget::default())
        .expect("lane");
    agent.subscribe(writer, channel).expect("subscribe");
    agent
        .send(writer, channel, Value::text("x"), &[])
        .expect("send");

    // The receive path is the one that cannot be an oracle for a lane.
    assert_eq!(
        agent
            .recv(outsider, channel)
            .expect_err("a non-subscriber is refused")
            .code(),
        "rpc/unknown-channel"
    );

    // The host is a different principal: it already owns the kernel, and the
    // ADRs say it sees the counts.
    let stats = agent.channel(channel).expect("the host sees the channel");
    assert_eq!(stats.name, "hidden");
    assert_eq!(stats.queued, 1);
    assert_eq!(stats.subscribers, 1);
}
