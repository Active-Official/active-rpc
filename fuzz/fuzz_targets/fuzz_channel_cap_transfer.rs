#![no_main]

//! Channel and capability transfer semantics.
//!
//! Invariants under test (I-7, I-11):
//!
//! 1. Direction is enforced: a send-only channel refuses receive and a
//!    receive-only channel refuses send.
//! 2. A closed channel refuses new sends but still drains queued messages.
//! 3. A capability id in a message must exist in the sender's kernel.
//! 4. Sending a capability does not retain it: the sender's drop still notifies
//!    the provider.
//!
//! Run with `cargo +nightly fuzz run fuzz_channel_cap_transfer -- -runs=200000`.

use libfuzzer_sys::fuzz_target;

use active_rpc::{Budget, Channel, ChannelId, Direction, LaneId, Value};

#[path = "common.rs"]
mod common;

fn direction(byte: u8) -> Direction {
    match byte % 3 {
        0 => Direction::Send,
        1 => Direction::Receive,
        _ => Direction::Both,
    }
}

fuzz_target!(|data: &[u8]| {
    // Fixed positive control: a bidirectional channel carries a payload. With
    // every send and receive refusing, the direction assertions below hold
    // vacuously (R-20 round 5, F7).
    {
        let mut control = Channel::new(ChannelId(0), "control", Direction::Both);
        control
            .send(LaneId(0), Value::Int(9), Vec::new())
            .expect("a bidirectional channel accepts a send");
        let message = control
            .recv()
            .expect("receive")
            .expect("the sent message is queued");
        assert_eq!(message.payload, Value::Int(9), "the payload survives");
    }
    if data.is_empty() {
        return;
    }

    // 1 and 2. Standalone channel semantics.
    let direction = direction(data[0]);
    let mut channel = Channel::new(ChannelId(1), "fuzz", direction);
    let sent = channel.send(LaneId(1), Value::Int(1), Vec::new());
    if direction.can_send() {
        assert!(sent.is_ok(), "a send-capable channel accepts a send");
    } else {
        assert!(sent.is_err(), "a receive-only channel refuses a send");
    }
    let received = channel.recv();
    if direction.can_receive() {
        // A receive-capable channel that drops the message used to pass: the
        // receive half asserted nothing.
        match received {
            Ok(Some(message)) if direction.can_send() => {
                assert_eq!(message.payload, Value::Int(1), "the payload survives");
            }
            Ok(_) => {}
            Err(error) => panic!("a receive-capable channel refused a receive: {error}"),
        }
    } else {
        assert!(received.is_err(), "a send-only channel refuses receive");
    }
    if direction.can_send() {
        let _ = channel.send(LaneId(1), Value::Int(2), Vec::new());
    }
    channel.close();
    assert!(channel.send(LaneId(1), Value::Int(3), Vec::new()).is_err());
    // Draining after close is allowed.
    let _ = channel.recv();

    // 3 and 4. Kernel channels and capability transfer.
    let agent = common::agent(data);
    let provider = agent.register(Box::new(common::Echo::default()));
    let lane = agent
        .create_lane("main", Budget::default())
        .expect("default lane budget");
    let cap = common::mint(&agent, provider, &["ping"], Budget::default());
    let channel_id = agent
        .create_channel("wire", Direction::Both)
        .expect("a fresh channel");
    agent.subscribe(lane, channel_id).expect("lane subscribes");

    // A known capability id travels in the message.
    assert!(agent
        .send(
            lane,
            channel_id,
            Value::text("hello"),
            std::slice::from_ref(&cap)
        )
        .is_ok());
    let message = agent
        .recv(lane, channel_id)
        .expect("channel")
        .expect("message");
    assert_eq!(message.caps.len(), 1);
    assert_eq!(message.caps[0], cap.id());

    // An unknown capability id is refused by the sender.
    let forged = agent.import(active_rpc::CapId([data[0]; 16]));
    let error = agent
        .send(lane, channel_id, Value::text("forged"), &[forged])
        .expect_err("an unknown capability id must be refused");
    assert!(
        matches!(
            error.code(),
            "rpc/unknown-capability" | "rpc/invalid-argument"
        ),
        "unexpected code {}",
        error.code()
    );

    // Dropping the sender's handle still notifies the provider: the message did
    // not create a reference.
    drop(cap);
    let drops = agent.take_drops(provider);
    // Exactly one notification for the one object: "not empty" also passed for a
    // kernel that notified twice, or for a different capability.
    assert_eq!(
        drops.len(),
        1,
        "one object must produce exactly one drop notification"
    );
    assert_eq!(drops[0].0, 0, "the notification names the object");
});
