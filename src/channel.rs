//! Channels: named streams of messages and capability transfers.
//!
//! A channel is a typed, named stream between lanes of one agent. Direction is
//! declared up front; a receive-only channel refuses sends, and a send-only
//! channel refuses receives.
//!
//! Capabilities named in a message are **shared (borrowed)**, not copied or
//! moved: the ids travel, the sender keeps its handles, and the receiver's
//! authority is whatever its own kernel registry already holds. Across agents
//! the same ids travel in an envelope's capability table and each receiver looks
//! them up in its own registry — authority never transfers implicitly, which is
//! why a channel message cannot inflate a reference count.

use std::collections::{BTreeSet, VecDeque};

use crate::cap::CapId;
use crate::error::{Error, Result};
use crate::lane::LaneId;
use crate::value::Value;

/// Channel identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChannelId(pub u64);

impl std::fmt::Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ch{}", self.0)
    }
}

/// Allowed traffic direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// The lane may only send.
    Send,
    /// The lane may only receive.
    Receive,
    /// Both directions.
    Both,
}

impl Direction {
    pub fn can_send(self) -> bool {
        matches!(self, Direction::Send | Direction::Both)
    }

    pub fn can_receive(self) -> bool {
        matches!(self, Direction::Receive | Direction::Both)
    }
}

/// One message on a channel.
#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    /// Sending lane.
    pub from: LaneId,
    /// Payload value (never secret material).
    pub payload: Value,
    /// Capabilities transferred with this message.
    pub caps: Vec<CapId>,
    /// Monotonic sequence within the channel.
    pub sequence: u64,
}

/// A named channel.
#[derive(Debug, Clone)]
pub struct Channel {
    pub id: ChannelId,
    pub name: String,
    pub direction: Direction,
    queue: VecDeque<Message>,
    next_sequence: u64,
    closed: bool,
    pub subscribers: BTreeSet<u64>,
    /// Total messages sent (including those already received).
    pub sent: u64,
    /// Total messages received.
    pub received: u64,
}

impl Channel {
    pub fn new(id: ChannelId, name: impl Into<String>, direction: Direction) -> Self {
        Self {
            id,
            name: name.into(),
            direction,
            queue: VecDeque::new(),
            next_sequence: 0,
            closed: false,
            subscribers: BTreeSet::new(),
            sent: 0,
            received: 0,
        }
    }

    /// Whether the channel accepts sends.
    pub fn can_send(&self) -> bool {
        self.direction.can_send() && !self.closed
    }

    /// Whether the channel has messages for a receiver.
    pub fn can_receive(&self) -> bool {
        self.direction.can_receive() && !self.queue.is_empty()
    }

    /// Queue a message.
    pub fn send(&mut self, from: LaneId, payload: Value, caps: Vec<CapId>) -> Result<Message> {
        if self.closed {
            return Err(Error::InvalidArgument("channel is closed"));
        }
        if !self.direction.can_send() {
            return Err(Error::InvalidArgument("channel is receive-only"));
        }
        let message = Message {
            from,
            payload,
            caps,
            sequence: self.next_sequence,
        };
        self.next_sequence += 1;
        self.sent += 1;
        self.queue.push_back(message.clone());
        Ok(message)
    }

    /// Take the oldest message.
    pub fn recv(&mut self) -> Result<Option<Message>> {
        if !self.direction.can_receive() {
            return Err(Error::InvalidArgument("channel is send-only"));
        }
        match self.queue.pop_front() {
            Some(message) => {
                self.received += 1;
                Ok(Some(message))
            }
            None => Ok(None),
        }
    }

    /// Peek at the oldest message without consuming it.
    pub fn peek(&self) -> Option<&Message> {
        self.queue.front()
    }

    /// Number of queued messages.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Close the channel: further sends and receives fail.
    pub fn close(&mut self) {
        self.closed = true;
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }
}
