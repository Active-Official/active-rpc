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

/// Maximum messages queued on one channel.
///
/// A channel is a mailbox, not an unbounded log. The ceiling is high enough for
/// a burst and finite so one sender with a valid capability cannot grow kernel
/// memory without bound.
pub const MAX_QUEUED_PER_CHANNEL: usize = 4_096;

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
    /// Whether this direction permits sending.
    pub fn can_send(self) -> bool {
        matches!(self, Direction::Send | Direction::Both)
    }

    /// Whether this direction permits receiving.
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
    /// Topic this message was published on, when the publisher named one.
    pub topic: Option<String>,
    /// Monotonic sequence within the channel.
    pub sequence: u64,
}

/// A named channel.
#[derive(Debug, Clone)]
pub struct Channel {
    /// Kernel-assigned identifier.
    pub id: ChannelId,
    /// The name a peer subscribes by.
    pub name: String,
    /// Which ways messages may flow.
    pub direction: Direction,
    queue: VecDeque<Message>,
    next_sequence: u64,
    closed: bool,
    /// Lanes subscribed to this channel.
    pub subscribers: BTreeSet<u64>,
    /// Total messages sent (including those already received).
    pub sent: u64,
    /// Total messages received.
    pub received: u64,
}

impl Channel {
    /// Create an open channel with an empty queue.
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

    /// Number of queued messages not yet received.
    pub fn queued(&self) -> usize {
        self.queue.len()
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
        self.send_topic(from, None, payload, caps)
    }

    /// Queue a message on a topic.
    pub fn send_topic(
        &mut self,
        from: LaneId,
        topic: Option<&str>,
        payload: Value,
        caps: Vec<CapId>,
    ) -> Result<Message> {
        if self.closed {
            return Err(Error::InvalidArgument("channel is closed"));
        }
        if !self.direction.can_send() {
            return Err(Error::InvalidArgument("channel is receive-only"));
        }
        if self.queue.len() >= MAX_QUEUED_PER_CHANNEL {
            return Err(Error::BudgetExceeded("channel queue"));
        }
        let message = Message {
            from,
            payload,
            caps,
            topic: topic.map(str::to_string),
            sequence: self.next_sequence,
        };
        self.next_sequence += 1;
        self.sent += 1;
        self.queue.push_back(message.clone());
        Ok(message)
    }

    /// Take the oldest message.
    pub fn recv(&mut self) -> Result<Option<Message>> {
        self.take_at(0)
    }

    /// Take the oldest message published on `topic`.
    ///
    /// Messages on other topics stay queued, in order.
    pub fn recv_topic(&mut self, topic: &str) -> Result<Option<Message>> {
        if !self.direction.can_receive() {
            return Err(Error::InvalidArgument("channel is send-only"));
        }
        let index = self
            .queue
            .iter()
            .position(|message| message.topic.as_deref() == Some(topic));
        match index {
            Some(index) => self.take_at(index),
            None => Ok(None),
        }
    }

    fn take_at(&mut self, index: usize) -> Result<Option<Message>> {
        if !self.direction.can_receive() {
            return Err(Error::InvalidArgument("channel is send-only"));
        }
        match self.queue.remove(index) {
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

    /// Whether the queue holds no messages.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Close the channel: further sends fail; messages already queued remain
    /// receivable.
    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Whether the channel has been closed.
    pub fn is_closed(&self) -> bool {
        self.closed
    }
}
