//! R-17 round 5, L-4: a drained channel releases the queue's allocation.
//!
//! `take_at` removed records but never shrank the deque, so 4 096 drained
//! channels kept ~1.6 GiB resident while both byte counters read zero. A live
//! allocation counter makes the release observable.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use active_rpc::channel::{Channel, ChannelId, Direction, MESSAGE_OVERHEAD};
use active_rpc::lane::LaneId;
use active_rpc::value::Value;

struct Live;

static LIVE: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every method forwards to the system allocator unchanged; the counter
// is the only addition, and it is atomic.
unsafe impl GlobalAlloc for Live {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE.fetch_add(layout.size(), Ordering::SeqCst);
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
    assert!(
        charged >= MESSAGE_OVERHEAD + 100_000 * slot,
        "the occupied slots are charged: {charged}"
    );
    assert!(
        charged <= MESSAGE_OVERHEAD + 2 * slot + 100_000 * slot,
        "the slots are charged twice: {charged}"
    );
    drop(value);
}
