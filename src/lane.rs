//! Lanes: independent concurrent execution contexts inside one agent.
//!
//! A lane is a **budget and lifecycle scope**, not an authority boundary: any
//! lane may call any live capability (authority lives on the capability), and a
//! lane cannot gate another lane's work. What a lane owns is its call and byte
//! ceiling, its pending/completed counters and its channel subscriptions (which
//! are advisory).
//!
//! Scheduling is per provider, not per lane: a batch holds the runnable jobs of
//! one provider in queue order, and two lanes interleave because their jobs are
//! queued in the order they were issued.

use std::collections::BTreeSet;

use crate::budget::Budget;
use crate::error::{Error, Result};

/// Identity of a lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LaneId(pub u64);

impl std::fmt::Display for LaneId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "lane{}", self.0)
    }
}

/// A lane's state.
#[derive(Debug, Clone)]
pub struct Lane {
    /// Kernel-assigned identifier.
    pub id: LaneId,
    /// The name the caller chose.
    pub name: String,
    /// The lane's own call and byte ceiling.
    pub budget: Budget,
    /// Calls issued by this lane that have not completed.
    pub pending: u32,
    /// Completed calls.
    pub completed: u64,
    /// Bytes moved through this lane (calls and publishes).
    pub bytes: u64,
    /// Channels this lane is subscribed to.
    ///
    /// Subscription is advisory: the kernel does not use it to gate receives.
    pub channels: BTreeSet<u64>,
    /// True once the lane has been destroyed; further calls are refused.
    pub closed: bool,
}

impl Lane {
    /// Create an open lane with its own budget.
    pub fn new(id: LaneId, name: impl Into<String>, budget: Budget) -> Self {
        Self {
            id,
            name: name.into(),
            budget,
            pending: 0,
            completed: 0,
            bytes: 0,
            channels: BTreeSet::new(),
            closed: false,
        }
    }

    /// Attenuate a lane's budget; refuses widening.
    pub fn attenuate(&mut self, budget: Budget) -> Result<()> {
        if !budget.is_attenuation_of(&self.budget) {
            return Err(Error::Escalation("lane budget grows"));
        }
        self.budget = budget;
        Ok(())
    }

    /// Record a completed call against the lane.
    pub fn complete(&mut self) {
        self.completed += 1;
        self.pending = self.pending.saturating_sub(1);
    }

    /// Close the lane.
    pub fn destroy(&mut self) {
        self.closed = true;
        self.pending = 0;
    }

    /// Whether the lane may issue another call under its budget.
    ///
    /// Pending calls count: queueing a thousand calls before `run()` must not
    /// let a lane outspend its grant.
    pub fn has_capacity(&self) -> bool {
        !self.closed && self.completed.saturating_add(self.pending as u64) < self.budget.max_calls
    }
}
