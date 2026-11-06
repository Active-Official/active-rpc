//! A send must move the payload, not copy it.
//!
//! `Channel::push` returns the message it queued, which costs a clone of the
//! value. The kernel's send path only needs the sequence, so it used to pay that
//! clone on every message: 64 MiB copied per send at the frame ceiling, and two
//! copies resident in the kernel. A counting allocator makes the difference
//! visible: the shipped `send_sequence` must not allocate payload-sized memory.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use active_rpc::cap::CapAttrs;
use active_rpc::channel::{Channel, ChannelId, Direction};
use active_rpc::kernel::Provider;
use active_rpc::lane::LaneId;
use active_rpc::value::{Call, Response, Value};
use active_rpc::{Agent, Budget};

struct Counting;

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

/// The counter is process-wide, so the allocation tests take turns: another
/// test's payload allocation on a parallel thread would land inside the window
/// this file measures.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

// SAFETY: every method forwards to the system allocator unchanged; the counters
// are the only addition, and they are atomic.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATED.fetch_add(layout.size(), Ordering::SeqCst);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATED.fetch_add(new_size.saturating_sub(layout.size()), Ordering::SeqCst);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

const PAYLOAD: usize = 1 << 20;

#[test]
fn a_kernel_send_does_not_copy_the_payload() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let mut channel = Channel::new(ChannelId(1), "copy", Direction::Both);
    // The payload exists before the measurement: only the send is timed.
    let payload = Value::Text("x".repeat(PAYLOAD));

    let before = ALLOCATED.load(Ordering::SeqCst);
    let sequence = channel
        .send_sequence(LaneId(1), payload, Vec::new())
        .expect("send");
    let during = ALLOCATED.load(Ordering::SeqCst).saturating_sub(before);

    assert_eq!(sequence, 0);
    assert!(
        during < PAYLOAD / 4,
        "a send allocated {during} bytes for a {PAYLOAD} byte payload"
    );
    // The message did arrive, and it is the only copy: the channel holds it.
    assert_eq!(channel.len(), 1);
    assert_eq!(
        channel.queued_bytes(),
        Channel::message_bytes(&channel.peek().expect("queued").payload, &[], None)
    );
}

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
fn a_publish_does_not_copy_the_payload() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    // Round 2 (#1): `publish` still went through `send_topic`, which clones the
    // message it queued. The kernel needs the sequence only.
    let agent = Agent::with_secret([0x7e; 32]);
    let provider = agent.register(Box::new(Sink));
    let cap = agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["noop"]).restrict_topics(&["t"]),
        )
        .expect("cap");
    let lane = agent
        .create_lane("publisher", Budget::default())
        .expect("lane");
    let channel = agent
        .create_channel("publish", Direction::Both)
        .expect("channel");
    let payload = Value::Text("x".repeat(PAYLOAD));

    let before = ALLOCATED.load(Ordering::SeqCst);
    agent
        .publish(lane, channel, &cap, "t", payload)
        .expect("publish");
    let during = ALLOCATED.load(Ordering::SeqCst).saturating_sub(before);

    assert!(
        during < PAYLOAD / 4,
        "a publish allocated {during} bytes for a {PAYLOAD} byte payload"
    );
}

#[test]
fn a_direct_send_still_returns_the_queued_message() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let mut channel = Channel::new(ChannelId(2), "copy", Direction::Both);
    let message = channel
        .send(LaneId(2), Value::Int(7), Vec::new())
        .expect("send");
    assert_eq!(message.payload, Value::Int(7));
    assert_eq!(message.sequence, 0);
    assert_eq!(channel.peek(), Some(&message));
}

/// A refusal is attributed to the capability that caused it, or to the lane when
/// a transfer names several: the round-3 reviewer's `caps.first()` tape blamed
/// the first capability for the third one's refusal (R-15 round 3, #1).
#[test]
fn a_multi_capability_send_does_not_blame_the_first_capability() {
    use active_rpc::Event;

    let agent = Agent::with_secret([0x7f; 32]);
    let provider = agent.register(Box::new(Sink));
    let allowed = agent
        .mint(provider, 0, CapAttrs::new(&["noop"]))
        .expect("cap");
    let revoked = agent
        .mint(provider, 1, CapAttrs::new(&["noop"]))
        .expect("cap");
    agent.revoke(&revoked).expect("revoke");
    let lane = agent
        .create_lane("attribution", Budget::default())
        .expect("lane");
    let channel = agent
        .create_channel("attribution", Direction::Both)
        .expect("channel");

    let error = agent
        .send(lane, channel, Value::text("x"), &[allowed.clone(), revoked])
        .expect_err("a revoked capability cannot be transferred");
    assert_eq!(error.code(), "rpc/revoked", "{error}");

    let refused = agent
        .events()
        .into_iter()
        .find_map(|event| match event {
            Event::CallRefused { cap, code, .. } if code == "rpc/revoked" => Some(cap),
            _ => None,
        })
        .expect("the refusal is on the tape");
    assert_eq!(
        refused, None,
        "a multi-capability refusal names the lane, not the first capability"
    );
}
