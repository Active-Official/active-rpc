//! Shared-memory transport.
//!
//! A segment holds length-prefixed frames in a ring. The producer appends a
//! frame and publishes it; the consumer either copies it out
//! ([`SharedSegment::read`]) or borrows it in place
//! ([`SharedSegment::with_frame`]) — the latter avoids copying the frame out of
//! the ring, and the test asserts the borrowed slice points inside the segment.
//! A decoded [`Envelope`] still owns its payload: this is one copy fewer, not a
//! borrowed envelope.
//!
//! The layout is what a memory-mapped segment needs for cross-process use; only
//! the storage strategy changes (ADR-0003 in this crate).
//!
//! ```text
//! data: u32 length | payload | u32 length | payload | ...
//! ```
//!
//! The implementation uses a mutex around the indices and bytes rather than
//! atomics plus raw pointers, so the crate keeps `#![forbid(unsafe_code)]` and
//! the ring is safe under concurrent producers and consumers. A frame that does
//! not fit is refused (`rpc/transport`) instead of overwriting unread data.

use std::sync::{Arc, Mutex};

use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::wire::{Envelope, WireLimits};

#[derive(Debug)]
struct SegmentState {
    data: Vec<u8>,
    head: u64,
    tail: u64,
    capacity: usize,
    /// Lifetime byte totals. `head` and `tail` return to zero when the ring
    /// drains, so they cannot serve as counters: a consumer that watched them
    /// saw the totals jump backwards.
    produced_total: u64,
    consumed_total: u64,
    /// Frames produced and consumed over the life of the segment.
    frames_produced: u64,
    frames_consumed: u64,
}

/// A shared segment: a byte ring shared by producer and consumer.
#[derive(Debug)]
pub struct SharedSegment {
    state: Mutex<SegmentState>,
}

impl SharedSegment {
    /// Allocate a segment with at least `payload_bytes` of frame space.
    pub fn new(payload_bytes: usize) -> Arc<SharedSegment> {
        let capacity = payload_bytes.max(1024);
        Arc::new(SharedSegment {
            state: Mutex::new(SegmentState {
                data: vec![0u8; capacity],
                head: 0,
                tail: 0,
                capacity,
                produced_total: 0,
                consumed_total: 0,
                frames_produced: 0,
                frames_consumed: 0,
            }),
        })
    }

    /// Usable frame bytes.
    pub fn capacity(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .capacity
    }

    /// Bytes published and not yet consumed.
    pub fn available(&self) -> usize {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        usize::try_from(state.head.saturating_sub(state.tail)).unwrap_or(usize::MAX)
    }

    /// Total bytes written into the ring, since the segment was created.
    pub fn produced(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .produced_total
    }

    /// Total bytes consumed from the ring, since the segment was created.
    pub fn consumed(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .consumed_total
    }

    /// Frames written into the ring, since the segment was created.
    pub fn frames_produced(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .frames_produced
    }

    /// Frames consumed from the ring, since the segment was created.
    pub fn frames_consumed(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .frames_consumed
    }

    /// Write a frame. Fails when the ring cannot take it.
    pub fn write(&self, payload: &[u8]) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let used = usize::try_from(state.head.saturating_sub(state.tail)).unwrap_or(usize::MAX);
        // The length prefix is four bytes: a payload past `u32::MAX` would wrap
        // and the reader would take the tail as a second frame. The segment
        // ceiling makes this unreachable in practice, and the conversion keeps
        // the invariant independent of it (round 35, R-09 #3).
        let length =
            u32::try_from(payload.len()).map_err(|_| Error::Wire("frame length overflow"))?;
        let needed = payload.len() + 4;
        if needed > state.capacity {
            return Err(Error::Transport(
                "frame does not fit the segment".to_string(),
            ));
        }
        // A desynchronised consumer can advance past the frame boundary and
        // leave `tail` mid-frame. Check this before the capacity decision so the
        // failure names the real cause instead of reporting a full segment.
        if used > state.capacity {
            state.head = 0;
            state.tail = 0;
            return Err(Error::Transport(
                "shared segment desynchronised".to_string(),
            ));
        }
        if used + needed > state.capacity {
            return Err(Error::Transport("shared segment is full".to_string()));
        }
        let start = (state.head % state.capacity as u64) as usize;
        if start + needed > state.capacity {
            // Compact instead of fragmenting the frame: move the unread bytes
            // from the *tail* to the front. A contiguous unread region moves in
            // place; a wrapped one is copied through a temporary because its two
            // pieces can overlap the destination.
            let unread = used;
            let capacity = state.capacity;
            let tail_start = (state.tail % capacity as u64) as usize;
            if tail_start + unread <= capacity {
                state.data.copy_within(tail_start..tail_start + unread, 0);
            } else {
                let first = capacity - tail_start;
                let mut compacted = Vec::with_capacity(unread);
                compacted.extend_from_slice(&state.data[tail_start..capacity]);
                compacted.extend_from_slice(&state.data[0..unread - first]);
                state.data[..unread].copy_from_slice(&compacted);
            }
            state.head = unread as u64;
            state.tail = 0;
        }
        let start = (state.head % state.capacity as u64) as usize;
        state.data[start..start + 4].copy_from_slice(&length.to_le_bytes());
        state.data[start + 4..start + 4 + payload.len()].copy_from_slice(payload);
        state.head += needed as u64;
        state.produced_total = state.produced_total.saturating_add(needed as u64);
        state.frames_produced = state.frames_produced.saturating_add(1);
        Ok(())
    }

    /// Consume one frame, returning a copy.
    pub fn read(&self) -> Result<Option<Vec<u8>>> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((start, len)) = frame_bounds(&state)? else {
            return Ok(None);
        };
        let frame = state.data[start..start + len].to_vec();
        consume(&mut state, len);
        Ok(Some(frame))
    }

    /// Borrow the oldest frame in place without releasing it.
    ///
    /// The closure runs under the segment lock, so the bytes cannot move while
    /// it looks at them. It must not call back into this segment: the lock is
    /// not re-entrant and a nested call would deadlock. Decoding under the lock
    /// is what [`SharedMemoryTransport::recv_in_segment`] does, at the cost of
    /// holding the segment for one decode.
    pub fn with_frame<R>(&self, inspect: impl FnOnce(&[u8]) -> R) -> Result<Option<R>> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((start, len)) = frame_bounds(&state)? else {
            return Ok(None);
        };
        Ok(Some(inspect(&state.data[start..start + len])))
    }

    /// Inspect and consume the oldest frame atomically.
    ///
    /// The same re-entrancy contract as [`SharedSegment::with_frame`] applies.
    pub fn pop_frame<R>(&self, inspect: impl FnOnce(&[u8]) -> R) -> Result<Option<R>> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((start, len)) = frame_bounds(&state)? else {
            return Ok(None);
        };
        let result = inspect(&state.data[start..start + len]);
        consume(&mut state, len);
        Ok(Some(result))
    }

    /// Release the oldest frame.
    ///
    /// The length comes from the frame header, so the ring can never be advanced
    /// to a point that is not a frame boundary: a caller-supplied length used to
    /// leave `tail` inside a payload, whose first four bytes then read as the
    /// next length and bricked the ring.
    pub fn advance(&self) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((_start, len)) = frame_bounds(&state)? else {
            return Ok(());
        };
        consume(&mut state, len);
        Ok(())
    }

    /// Reset the indices.
    pub fn reset(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.head = 0;
        state.tail = 0;
    }
}

/// Advance past a frame of `len` payload bytes and account for it.
fn consume(state: &mut SegmentState, len: usize) {
    state.tail += len as u64 + 4;
    state.consumed_total = state.consumed_total.saturating_add(len as u64 + 4);
    state.frames_consumed = state.frames_consumed.saturating_add(1);
    if state.tail >= state.head {
        state.tail = 0;
        state.head = 0;
    }
}

fn frame_bounds(state: &SegmentState) -> Result<Option<(usize, usize)>> {
    if state.head == state.tail {
        return Ok(None);
    }
    let start = (state.tail % state.capacity as u64) as usize;
    if start + 4 > state.capacity {
        return Err(Error::Wire("frame header straddles the ring end"));
    }
    let len =
        u32::from_le_bytes(state.data[start..start + 4].try_into().expect("4 bytes")) as usize;
    if start + 4 + len > state.capacity {
        return Err(Error::Wire("frame straddles the ring end"));
    }
    if state.tail + len as u64 + 4 > state.head {
        // A short frame is a framing fault on every transport (round 11,
        // R-09 #3).
        return Err(Error::Wire("truncated frame"));
    }
    Ok(Some((start + 4, len)))
}

/// A transport adapter over a shared segment.
#[derive(Debug)]
pub struct SharedMemoryTransport {
    segment: Arc<SharedSegment>,
    limits: WireLimits,
    written: u64,
}

impl SharedMemoryTransport {
    /// Wrap a segment.
    pub fn new(segment: Arc<SharedSegment>) -> Self {
        Self {
            segment,
            limits: WireLimits::default(),
            written: 0,
        }
    }

    /// Use tighter limits.
    pub fn with_limits(mut self, limits: WireLimits) -> Self {
        self.limits = limits;
        self
    }

    /// The underlying segment.
    pub fn segment(&self) -> &Arc<SharedSegment> {
        &self.segment
    }

    /// Decode the next frame while the segment's lock is held.
    ///
    /// The *frame bytes* are borrowed from the ring, so the transport does not
    /// copy them out first. The decoded [`Envelope`] owns its payload, so this
    /// is one copy fewer than [`Transport::recv`], not a borrowed envelope. It
    /// costs the segment lock for the duration of one decode.
    pub fn recv_in_segment(&mut self) -> Result<Option<Envelope>> {
        let limits = self.limits;
        self.segment
            .pop_frame(|frame| Envelope::decode_with(frame, limits))?
            .transpose()
    }
}

impl Transport for SharedMemoryTransport {
    fn name(&self) -> &'static str {
        "shared-memory"
    }

    fn send(&mut self, envelope: &Envelope) -> Result<()> {
        let bytes = envelope.encode_with_limits(self.limits)?;
        // The segment framing carries a 32-bit length and the peer reads at
        // most `MAX_FRAME_BYTES`: a larger `limits` must not emit a frame no
        // reader accepts (round 10, R-09 #7).
        if bytes.len() > self.limits.max_bytes.min(crate::transport::MAX_FRAME_BYTES) {
            return Err(Error::Wire("envelope exceeds the size ceiling"));
        }
        self.segment.write(&bytes)?;
        self.written += (bytes.len() + 4) as u64;
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Envelope>> {
        let Some(frame) = self.segment.read()? else {
            return Ok(None);
        };
        Ok(Some(Envelope::decode_with(&frame, self.limits)?))
    }

    fn bytes_written(&self) -> u64 {
        self.written
    }
}
