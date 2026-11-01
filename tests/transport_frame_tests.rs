//! Frame-layer oracles that need a measuring allocator.
//!
//! One test binary, one test at a time, so the live-byte count belongs to the
//! call under test. `read_frame` is the single place every byte transport reads
//! a length prefix, and the review measured that a four-byte header used to
//! reserve 64 MiB before the peer sent anything.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};

use active_rpc::transport::read_frame;
use active_rpc::wire::WireLimits;

struct Tracking;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: Tracking = Tracking;

/// A reader that delivers a fixed prefix and then end of stream.
struct PrefixReader {
    prefix: Vec<u8>,
    position: usize,
}

impl Read for PrefixReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let left = &self.prefix[self.position..];
        let take = left.len().min(buffer.len());
        buffer[..take].copy_from_slice(&left[..take]);
        self.position += take;
        Ok(take)
    }
}

#[test]
fn a_maximum_length_header_does_not_reserve_the_body() {
    // The header announces the transport ceiling; the peer then sends nothing.
    let mut reader = PrefixReader {
        prefix: (active_rpc::transport::MAX_FRAME_BYTES as u32)
            .to_le_bytes()
            .to_vec(),
        position: 0,
    };
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let error = read_frame(&mut reader, &WireLimits::default())
        .expect_err("a truncated body is a transport error");
    let peak = PEAK.load(Ordering::Relaxed);
    assert!(
        peak.saturating_sub(before) < (1 << 20),
        "the header reserved {} bytes before the body arrived",
        peak - before
    );
    let message = format!("{error}");
    assert!(
        message.contains("truncated frame body"),
        "unexpected error: {message}"
    );
}

#[test]
fn a_partial_header_at_end_of_stream_is_refused() {
    // Two of the four length bytes, then FIN: a clean close would let a cut
    // frame pass for an empty stream.
    let mut reader = PrefixReader {
        prefix: vec![0x10, 0x00],
        position: 0,
    };
    let error = read_frame(&mut reader, &WireLimits::default())
        .expect_err("a partial header is not a clean close");
    assert!(
        format!("{error}").contains("truncated frame header"),
        "{error}"
    );
}

#[test]
fn an_empty_stream_is_a_clean_close() {
    let mut reader = PrefixReader {
        prefix: Vec::new(),
        position: 0,
    };
    assert_eq!(
        read_frame(&mut reader, &WireLimits::default()).unwrap(),
        None
    );
}
