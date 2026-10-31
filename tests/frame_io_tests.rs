//! Frame I/O: one vectored write per frame, one buffered read per envelope.
//!
//! `write_frame` now sends the header and the body in one `write_vectored` call
//! and advances the slice list on a short write. These tests drive that path
//! with writers that accept a few bytes at a time, and pin the failure mode for
//! a writer that accepts nothing.

use std::io::{self, Write};

use active_rpc::transport::{frame, read_frame, write_frame};
use active_rpc::wire::{Envelope, WireLimits};

/// A writer that accepts at most `chunk` bytes per call.
struct Dribble {
    data: Vec<u8>,
    chunk: usize,
    calls: usize,
}

impl Dribble {
    fn new(chunk: usize) -> Self {
        Self {
            data: Vec::new(),
            chunk,
            calls: 0,
        }
    }
}

impl Write for Dribble {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let take = buf.len().min(self.chunk);
        self.data.extend_from_slice(&buf[..take]);
        self.calls += 1;
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A writer that never makes progress.
struct Stalled {
    calls: usize,
}

impl Write for Stalled {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        Ok(0)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_frame_survives_a_short_write_across_both_slices() {
    for chunk in [1usize, 3, 7, 64] {
        for size in [0usize, 1, 17, 1000, 70_000] {
            let body: Vec<u8> = (0..size).map(|index| (index % 251) as u8).collect();
            let mut writer = Dribble::new(chunk);
            write_frame(&mut writer, &body).expect("a short write still completes");
            assert_eq!(
                writer.data.len(),
                body.len() + 4,
                "chunk {chunk} size {size}: header plus body"
            );
            assert_eq!(
                &writer.data[..4],
                &frame(body.len()).expect("frame"),
                "the header is the little-endian length"
            );
            let decoded = read_frame(
                &mut std::io::Cursor::new(writer.data),
                &WireLimits::default(),
            )
            .expect("read")
            .expect("one frame");
            assert_eq!(decoded, body, "chunk {chunk} size {size}: body round trips");
        }
    }
}

#[test]
fn a_writer_that_accepts_nothing_is_an_error_not_a_spin() {
    let mut writer = Stalled { calls: 0 };
    let error = write_frame(&mut writer, b"body").expect_err("zero progress is refused");
    assert_eq!(error.code(), "rpc/transport");
    assert_eq!(writer.calls, 1, "the loop stops on the first zero write");
}

#[test]
fn a_partial_envelope_at_the_end_of_stream_is_refused() {
    // A header that promises 16 bytes followed by 3: the reader must fail rather
    // than return a short body.
    let mut bytes = frame(16).expect("frame").to_vec();
    bytes.extend_from_slice(&[1, 2, 3]);
    let error = read_frame(&mut std::io::Cursor::new(bytes), &WireLimits::default())
        .expect_err("a truncated body is an error");
    assert_eq!(error.code(), "rpc/transport");
}

#[test]
fn a_frame_over_the_limit_is_refused_before_allocating() {
    let limits = WireLimits {
        max_bytes: 8,
        ..WireLimits::default()
    };
    let mut bytes = frame(4096).expect("frame").to_vec();
    bytes.extend_from_slice(&[0u8; 4096]);
    let error = read_frame(&mut std::io::Cursor::new(bytes), &limits)
        .expect_err("a frame over the ceiling is refused");
    assert_eq!(error.code(), "rpc/wire");
}

#[test]
fn an_envelope_round_trips_through_the_frame_helpers() {
    let envelope = Envelope {
        payload: vec![0x5a; 300],
        ..Envelope::request(9, "ping", vec![active_rpc::Arg::text("x")])
    };
    let bytes = envelope.encode().expect("encode");
    let mut writer = Dribble::new(5);
    write_frame(&mut writer, &bytes).expect("frame the envelope");
    let body = read_frame(
        &mut std::io::Cursor::new(writer.data),
        &WireLimits::default(),
    )
    .expect("read")
    .expect("frame");
    let decoded = Envelope::decode(&body).expect("decode");
    assert_eq!(decoded.method, "ping");
    assert_eq!(decoded.payload, envelope.payload);
}
