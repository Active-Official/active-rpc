//! R-17 round 5, L-4: a drained channel releases the queue's allocation.
//!
//! `take_at` removed records but never shrank the deque, so 4 096 drained
//! channels kept ~1.6 GiB resident while both byte counters read zero. A live
//! allocation counter makes the release observable.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use active_rpc::channel::{Channel, ChannelId, Direction, MESSAGE_OVERHEAD, SLOTS_PER_RECORD};
use active_rpc::lane::LaneId;
use active_rpc::value::Value;

struct Live;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every method forwards to the system allocator unchanged; the counter
// is the only addition, and it is atomic.
unsafe impl GlobalAlloc for Live {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE.fetch_add(layout.size(), Ordering::SeqCst);
        ALLOCS.fetch_add(1, Ordering::SeqCst);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LIVE.fetch_add(new_size.saturating_sub(layout.size()), Ordering::SeqCst);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOCATOR: Live = Live;

/// The live counter is process-wide, so the tests take turns: a parallel test's
/// allocation would land inside the window each one measures.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn a_drained_channel_releases_its_queue_allocation() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let mut channel = Channel::new(ChannelId(1), "shrink", Direction::Both);
    // Small messages, so the queued records (not the payloads) are the large
    // allocation: 1 024 records is about 98 KiB of deque.
    for _ in 0..1_024 {
        channel
            .send_sequence(LaneId(1), Value::text("x"), Vec::new())
            .expect("send");
    }
    let filled = LIVE.load(Ordering::SeqCst);
    while channel.recv().expect("recv").is_some() {}
    assert_eq!(channel.len(), 0);
    let drained = LIVE.load(Ordering::SeqCst);
    assert!(
        drained + 4_096 < filled,
        "the queue kept its allocation after draining: {filled} -> {drained}"
    );
}

/// A channel that keeps one message must not pin the burst it once held
/// (R-17 round 7, F-4).
#[test]
fn a_channel_that_keeps_one_message_releases_the_burst() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let mut channel = Channel::new(ChannelId(2), "burst", Direction::Both);
    for _ in 0..4_096 {
        channel
            .send_sequence(LaneId(1), Value::text("x"), Vec::new())
            .expect("send");
    }
    let filled = LIVE.load(Ordering::SeqCst);
    for _ in 0..4_095 {
        assert!(channel.recv().expect("recv").is_some());
    }
    assert_eq!(channel.len(), 1);
    let held = LIVE.load(Ordering::SeqCst);
    assert!(
        held + 300_000 < filled,
        "the deque kept the burst allocation: {filled} -> {held}"
    );
}

/// A `BTreeMap` reserves an eleven-slot leaf node on its first insert, so a
/// map-heavy record must be charged the node, not a per-entry share
/// (R-17 round 8, #1).
#[test]
fn a_map_heavy_record_is_charged_what_it_pins() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let before = LIVE.load(Ordering::SeqCst);
    let value = Value::List(
        (0..1_000)
            .map(|index| {
                let mut map = std::collections::BTreeMap::new();
                map.insert(format!("k{index}"), Value::Int(index));
                Value::Map(map)
            })
            .collect(),
    );
    let pinned = (LIVE.load(Ordering::SeqCst) - before) as u64;
    let charged = Channel::message_bytes(&value, &[], None);
    assert!(
        charged.saturating_mul(5) >= pinned.saturating_mul(4),
        "charged {charged} for {pinned} pinned"
    );
    // The value's recursive drop is shallow here; a plain drop is fine.
    drop(value);
}

/// A list's occupied slots are charged as children and its spare slots as
/// capacity, not both (R-17 round 8, #2).
#[test]
fn a_list_is_not_charged_its_slots_twice() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let slot = std::mem::size_of::<Value>() as u64;
    let value = Value::List(vec![Value::Null; 100_000]);
    let charged = Channel::message_bytes(&value, &[], None);
    // The record's four slots are charged for residency on top of the
    // value's own slots (R-17 round 10, R10-1), so the bound is record slots
    // plus the list's occupied slots plus a little slack.
    let record = MESSAGE_OVERHEAD * SLOTS_PER_RECORD;
    assert!(
        charged >= record + 100_000 * slot,
        "the occupied slots are charged: {charged}"
    );
    assert!(
        charged <= record + 2 * slot + 100_000 * slot,
        "the slots are charged twice: {charged}"
    );
    drop(value);
}

/// A buffer keeps up to four times the live records; the byte charge must
/// cover that residency, or a drained channel charges a quarter of what it
/// holds (R-17 round 10, R10-1).
#[test]
fn a_channel_is_charged_for_the_slots_its_buffer_keeps() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let mut channel = Channel::new(ChannelId(5), "resident", Direction::Both);
    for _ in 0..4_096 {
        channel
            .send_sequence(LaneId(1), Value::Null, Vec::new())
            .expect("send");
    }
    for _ in 0..3_096 {
        channel.recv().expect("recv").expect("message");
    }
    let per_record = Channel::message_bytes(&Value::Null, &[], None);
    assert_eq!(
        channel.queued_bytes(),
        1_000 * per_record,
        "the counter and the per-record charge must agree"
    );
    assert!(
        per_record >= MESSAGE_OVERHEAD * SLOTS_PER_RECORD,
        "a record must be charged its share of the buffer: {per_record}"
    );
    // The buffer still holds about twice the live records at four slots each,
    // which is the residency the counter used to miss.
    assert!(
        channel.queued_bytes() >= MESSAGE_OVERHEAD * channel.capacity() as u64,
        "charged {} for a buffer of {} records",
        channel.queued_bytes(),
        channel.capacity()
    );
}

/// A standing queue must keep its capacity across message pairs: an exact
/// rebuild at the 2x threshold fired on every take, copying the whole queue
/// (R-17 round 9, F-1).
///
/// The queue is drained past the quarter-occupancy guard so the rebuild really
/// fires; filling 2 048 and draining 1 024 never crossed `4 * len < capacity`,
/// so the earlier form passed against the pre-fix exact rebuild too
/// (R-17 round 10, R10-2).
#[test]
fn a_steady_queue_keeps_its_capacity() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let mut channel = Channel::new(ChannelId(3), "steady", Direction::Both);
    for _ in 0..4_096 {
        channel
            .send_sequence(LaneId(1), Value::Null, Vec::new())
            .expect("send");
    }
    let full = channel.capacity();
    assert!(full >= 4_096, "the queue grew to {full}");
    // Exactly a quarter occupancy is still above the guard: a 2x threshold
    // rebuilt here, and at every later take the buffer was already at its live
    // count (R-17 round 10, R10-2).
    for _ in 0..3_072 {
        channel.recv().expect("recv").expect("message");
    }
    assert_eq!(channel.len(), 1_024, "the drain left the live count");
    assert_eq!(
        channel.capacity(),
        full,
        "the queue rebuilt at a quarter occupancy"
    );
    // One more take crosses `4 * len < capacity`, and the rebuild targets
    // twice the live records so the next push cannot satisfy the guard again.
    channel.recv().expect("recv").expect("message");
    let rebuilt = channel.capacity();
    // `VecDeque::with_capacity` rounds its request up, so the target is a
    // range: twice the live records plus the ring's slack, well under the
    // burst.
    assert!(
        (2_000..2_100).contains(&rebuilt),
        "the rebuild must target twice the live records (got {rebuilt}, full {full})"
    );
    assert!(rebuilt < full, "the burst capacity was not released");
    // Twice the live records leaves headroom for the next push, so a steady
    // pair loop neither reallocates nor rebuilds. The capacity check is the
    // assertion that binds: an exact rebuild at the guard leaves
    // `capacity() == len`, which fails it on the next take.
    for _ in 0..10_000 {
        channel
            .send_sequence(LaneId(1), Value::Null, Vec::new())
            .expect("send");
        channel.recv().expect("recv").expect("message");
    }
    assert_eq!(
        channel.capacity(),
        rebuilt,
        "the queue rebuilt or grew while its occupancy was steady"
    );
}

/// The depth refusal keeps the direction and capacity classes (R-17 round 9,
/// F-4).
#[test]
fn a_deep_payload_does_not_reclassify_a_direction_or_capacity_refusal() {
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let mut deep = Value::Null;
    for _ in 0..(active_rpc::wire::MAX_VALUE_DEPTH + 1) {
        deep = Value::List(vec![deep]);
    }
    let mut receive_only = Channel::new(ChannelId(4), "in", Direction::Receive);
    assert_eq!(
        receive_only
            .send_sequence(LaneId(1), deep.clone(), Vec::new())
            .expect_err("receive-only")
            .code(),
        "rpc/invalid-argument"
    );

    let mut full = Channel::new(ChannelId(5), "full", Direction::Both);
    for _ in 0..active_rpc::channel::MAX_QUEUED_PER_CHANNEL {
        full.send_sequence(LaneId(1), Value::Null, Vec::new())
            .expect("fill");
    }
    assert_eq!(
        full.send_sequence(LaneId(1), deep, Vec::new())
            .expect_err("full")
            .code(),
        "rpc/backpressure"
    );
}
