//! Shared-memory transport.
//!
//! A segment holds length-prefixed frames in a ring. The producer appends a
//! frame and publishes it; the consumer either copies it out
//! ([`SharedSegment::read`]) or borrows it in place
//! ([`SharedSegment::with_frame`]) — the latter is the zero-copy path a large
//! Infinity module takes, and the test asserts the borrowed slice points inside
//! the segment.
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
            }),
        })
    }

    /// Usable frame bytes.
    pub fn capacity(&self) -> usize {
        self.state.lock().expect("segment lock").capacity
    }

    /// Bytes published and not yet consumed.
    pub fn available(&self) -> usize {
        let state = self.state.lock().expect("segment lock");
        state.head.saturating_sub(state.tail) as usize
    }

    /// Total bytes written into the ring.
    pub fn produced(&self) -> u64 {
        self.state.lock().expect("segment lock").head
    }

    /// Total bytes consumed from the ring.
    pub fn consumed(&self) -> u64 {
        self.state.lock().expect("segment lock").tail
    }

    /// Write a frame. Fails when the ring cannot take it.
    pub fn write(&self, payload: &[u8]) -> Result<()> {
        let mut state = self.state.lock().expect("segment lock");
        let used = state.head.saturating_sub(state.tail) as usize;
        let needed = payload.len() + 4;
        if needed > state.capacity {
            return Err(Error::Transport(
                "frame does not fit the segment".to_string(),
            ));
        }
        if used + needed > state.capacity {
            return Err(Error::Transport("shared segment is full".to_string()));
        }
        let start = state.head as usize % state.capacity;
        if start + needed > state.capacity {
            // Compact instead of fragmenting the frame: move the unread bytes
            // to the front of the ring.
            let unread = used;
            state.data.copy_within(start..start + unread, 0);
            state.head = unread as u64;
            state.tail = 0;
        }
        let start = state.head as usize % state.capacity;
        state.data[start..start + 4].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        state.data[start + 4..start + 4 + payload.len()].copy_from_slice(payload);
        state.head += needed as u64;
        Ok(())
    }

    /// Consume one frame, returning a copy.
    pub fn read(&self) -> Result<Option<Vec<u8>>> {
        let mut state = self.state.lock().expect("segment lock");
        let Some((start, len)) = frame_bounds(&state)? else {
            return Ok(None);
        };
        let frame = state.data[start..start + len].to_vec();
        state.tail += len as u64 + 4;
        Ok(Some(frame))
    }

    /// Borrow the oldest frame in place (zero copy) without releasing it.
    ///
    /// The closure runs under the segment lock, so the bytes cannot move while
    /// it looks at them. For a single consumer this is safe; a consumer that
    /// decodes and consumes should use [`SharedSegment::pop_frame`], which
    /// advances under the same lock so two consumers cannot double-advance.
    pub fn with_frame<R>(&self, inspect: impl FnOnce(&[u8]) -> R) -> Result<Option<R>> {
        let state = self.state.lock().expect("segment lock");
        let Some((start, len)) = frame_bounds(&state)? else {
            return Ok(None);
        };
        Ok(Some(inspect(&state.data[start..start + len])))
    }

    /// Inspect and consume the oldest frame atomically (zero copy).
    pub fn pop_frame<R>(&self, inspect: impl FnOnce(&[u8]) -> R) -> Result<Option<R>> {
        let mut state = self.state.lock().expect("segment lock");
        let Some((start, len)) = frame_bounds(&state)? else {
            return Ok(None);
        };
        let result = inspect(&state.data[start..start + len]);
        state.tail += len as u64 + 4;
        if state.tail >= state.head {
            state.tail = 0;
            state.head = 0;
        }
        Ok(Some(result))
    }

    /// Release the oldest frame.
    pub fn advance(&self, len: usize) {
        let mut state = self.state.lock().expect("segment lock");
        state.tail += len as u64 + 4;
        if state.tail >= state.head {
            state.tail = 0;
            state.head = 0;
        }
    }

    /// Reset the indices.
    pub fn reset(&self) {
        let mut state = self.state.lock().expect("segment lock");
        state.head = 0;
        state.tail = 0;
    }
}

fn frame_bounds(state: &SegmentState) -> Result<Option<(usize, usize)>> {
    if state.head == state.tail {
        return Ok(None);
    }
    let start = state.tail as usize % state.capacity;
    if start + 4 > state.capacity {
        return Err(Error::Transport(
            "frame header straddles the ring end".to_string(),
        ));
    }
    let len =
        u32::from_le_bytes(state.data[start..start + 4].try_into().expect("4 bytes")) as usize;
    if start + 4 + len > state.capacity {
        return Err(Error::Transport("frame straddles the ring end".to_string()));
    }
    if state.tail + len as u64 + 4 > state.head {
        return Err(Error::Transport("truncated frame".to_string()));
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

    /// Decode the next frame in place, without copying it out of the segment.
    pub fn recv_zero_copy(&mut self) -> Result<Option<Envelope>> {
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
        let bytes = envelope.encode()?;
        if bytes.len() > self.limits.max_bytes {
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
