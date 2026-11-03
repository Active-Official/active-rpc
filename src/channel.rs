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

/// Largest queued payload a channel may hold, in bytes.
///
/// The message count alone is not a memory ceiling: 4 096 messages of the
/// largest frame a peer can send is 256 GiB. The byte ceiling is what a sender
/// actually has to pay for.
pub const MAX_QUEUED_BYTES: u64 = 64 << 20;

/// Wire size of one queued message: payload, transferred ids and topic name.
fn queued_size(payload: &Value, caps: &[CapId], topic: Option<&str>) -> u64 {
    payload
        .wire_size()
        .saturating_add((caps.len() as u64).saturating_mul(16))
        .saturating_add(topic.map_or(0, |name| name.len() as u64))
}

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

/// A message-free view of one channel.
///
/// [`Channel`] owns its queue, and a clone of it can `recv`: returning one from
/// `Agent::channel` handed every lane the mailbox, including the capability ids
/// a transfer queued, whether or not it had subscribed. This view cannot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelStats {
    /// Kernel-assigned identifier.
    pub id: ChannelId,
    /// Operator-facing name. A channel is addressed by its id; names are not
    /// unique and nothing looks a channel up by name.
    pub name: String,
    /// Which ways messages may flow.
    pub direction: Direction,
    /// Messages queued and not yet received.
    pub queued: usize,
    /// Payload bytes currently queued.
    pub queued_bytes: u64,
    /// Total messages sent (including those already received).
    pub sent: u64,
    /// Total messages received.
    pub received: u64,
    /// Lanes subscribed to this channel.
    pub subscribers: usize,
    /// Whether the channel refuses new sends.
    pub closed: bool,
}

/// A named channel.
#[derive(Debug, Clone)]
pub struct Channel {
    /// Kernel-assigned identifier.
    pub id: ChannelId,
    /// Operator-facing name. A channel is addressed by its id; names are not
    /// unique and nothing looks a channel up by name.
    pub name: String,
    /// Which ways messages may flow.
    pub direction: Direction,
    queue: VecDeque<Message>,
    next_sequence: u64,
    closed: bool,
    /// Lanes subscribed to this channel.
    pub subscribers: BTreeSet<u64>,
    /// Payload bytes currently queued.
    queued_bytes: u64,
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
            queued_bytes: 0,
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
        let bytes = queued_size(&payload, &caps, topic);
        self.push(from, topic, payload, caps, bytes)
    }

    /// Queue a message and return only its sequence.
    ///
    /// A caller that needs the sequence does not need the payload back: the
    /// clone in [`Channel::send_topic`] costs a full copy of the value (64 MiB
    /// at the frame ceiling).
    pub fn send_sequence(&mut self, from: LaneId, payload: Value, caps: Vec<CapId>) -> Result<u64> {
        let bytes = queued_size(&payload, &caps, None);
        // No clone: `push` copies the message for its return value, and a
        // kernel send has no use for it. At the frame ceiling that copy is
        // 64 MiB per send.
        self.enqueue(from, None, payload, caps, bytes)
    }

    /// Queue a message on a topic and return only its sequence.
    ///
    /// Like [`Channel::send_sequence`]: the queued message is the only copy.
    pub fn send_topic_sequence(
        &mut self,
        from: LaneId,
        topic: &str,
        payload: Value,
        caps: Vec<CapId>,
    ) -> Result<u64> {
        let bytes = queued_size(&payload, &caps, Some(topic));
        self.enqueue(from, Some(topic), payload, caps, bytes)
    }

    /// Whether the channel could hold `bytes` more.
    pub fn has_room_for(&self, bytes: u64) -> bool {
        self.queued_bytes.saturating_add(bytes) <= MAX_QUEUED_BYTES
    }

    /// Payload bytes a message with this shape would occupy.
    pub fn message_bytes(payload: &Value, caps: &[CapId], topic: Option<&str>) -> u64 {
        queued_size(payload, caps, topic)
    }

    fn push(
        &mut self,
        from: LaneId,
        topic: Option<&str>,
        payload: Value,
        caps: Vec<CapId>,
        bytes: u64,
    ) -> Result<Message> {
        self.enqueue(from, topic, payload, caps, bytes)?;
        // The queued copy is the only one worth keeping: returning it costs one
        // clone, and a direct `Channel` caller is the only caller that wants a
        // `Message` back.
        Ok(self
            .queue
            .back()
            .cloned()
            .expect("a message was just queued"))
    }

    /// Queue one message and return its sequence, without copying it.
    fn enqueue(
        &mut self,
        from: LaneId,
        topic: Option<&str>,
        payload: Value,
        caps: Vec<CapId>,
        bytes: u64,
    ) -> Result<u64> {
        if let Some(topic) = topic {
            // The type boundary enforces the same rule the kernel does: a
            // directly driven `Channel` cannot store a topic the kernel would
            // refuse.
            if !crate::kernel::valid_topic(topic) {
                return Err(Error::InvalidArgument(
                    "a topic must be 1..=128 bytes without control or reordering characters",
                ));
            }
        }
        if self.closed {
            return Err(Error::InvalidArgument("channel is closed"));
        }
        if !self.direction.can_send() {
            return Err(Error::InvalidArgument("channel is receive-only"));
        }
        if self.queue.len() >= MAX_QUEUED_PER_CHANNEL {
            // A full channel is backpressure, like the byte ceiling: the sender's
            // grant is untouched and the call can be retried later. Reporting a
            // spent budget here misclassified the refusal and charged the sender
            // a budget exhaustion it never earned.
            return Err(Error::Backpressure("channel queue ceiling reached"));
        }
        if !self.has_room_for(bytes) {
            // A full channel is backpressure, not a spent budget: the sender's
            // grant is untouched and the same call can be retried later.
            return Err(Error::Backpressure("channel byte ceiling reached"));
        }
        let message = Message {
            from,
            payload,
            caps,
            topic: topic.map(str::to_string),
            sequence: self.next_sequence,
        };
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        self.sent += 1;
        self.queued_bytes = self.queued_bytes.saturating_add(bytes);
        self.queue.push_back(message);
        Ok(sequence)
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
                let bytes = queued_size(&message.payload, &message.caps, message.topic.as_deref());
                self.queued_bytes = self.queued_bytes.saturating_sub(bytes);
                Ok(Some(message))
            }
            None => Ok(None),
        }
    }

    /// Peek at the oldest message without consuming it.
    pub fn peek(&self) -> Option<&Message> {
        self.queue.front()
    }

    /// Everything about this channel that is not a message.
    pub fn stats(&self) -> ChannelStats {
        ChannelStats {
            id: self.id,
            name: self.name.clone(),
            direction: self.direction,
            queued: self.queue.len(),
            queued_bytes: self.queued_bytes,
            sent: self.sent,
            received: self.received,
            subscribers: self.subscribers.len(),
            closed: self.closed,
        }
    }

    /// Payload bytes currently queued.
    pub fn queued_bytes(&self) -> u64 {
        self.queued_bytes
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
