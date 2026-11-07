//! R-17 round 3: the channel byte ceilings charge the message record, and the
//! receive path is the only one that hides a channel from a lane.
//!
//! `queued_size` used to charge payload bytes, transferred ids and the topic
//! name only. A one-byte message is a 96-byte record, so the "256 MiB" kernel
//! ceiling could hold roughly a hundred times that in records (L-1). The host
//! that holds `&Agent` also sees a channel's existence and counts regardless of
//! subscription, which is what the ADRs now say (L-3).

use active_rpc::channel::{
    Channel, ChannelId, Direction, Message, MAX_QUEUED_PER_CHANNEL, MESSAGE_OVERHEAD,
};
use active_rpc::kernel::{MAX_CHANNELS, MAX_QUEUED_CHANNEL_BYTES};
use active_rpc::lane::LaneId;
use active_rpc::value::Value;
use active_rpc::{Agent, Budget};

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
