//! Lanes: independent concurrent execution contexts inside one agent.
//!
//! A lane owns a budget and a set of channels and capabilities. The kernel
//! schedules lanes cooperatively: each step credits one ready job to one lane,
//! round-robin, so two lanes interleave deterministically and a lane that
//! exhausts its budget cannot starve another.

use std::collections::{BTreeSet, VecDeque};

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
    pub id: LaneId,
    pub name: String,
    pub budget: Budget,
    /// Calls issued by this lane that have not completed.
    pub pending: u32,
    /// Completed calls.
    pub completed: u64,
    /// Channels this lane is subscribed to.
    pub channels: BTreeSet<u64>,
    /// Capabilities minted for this lane.
    pub caps: BTreeSet<u128>,
    /// True once the lane has been destroyed; further calls are refused.
    pub closed: bool,
    /// Per-lane ready queue of job ids.
    pub ready: VecDeque<u64>,
}

impl Lane {
    pub fn new(id: LaneId, name: impl Into<String>, budget: Budget) -> Self {
        Self {
            id,
            name: name.into(),
            budget,
            pending: 0,
            completed: 0,
            channels: BTreeSet::new(),
            caps: BTreeSet::new(),
            closed: false,
            ready: VecDeque::new(),
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
        self.ready.clear();
        self.pending = 0;
    }

    /// Whether the lane may issue another call under its budget.
    pub fn has_capacity(&self) -> bool {
        !self.closed && self.completed < self.budget.max_calls
    }
}
