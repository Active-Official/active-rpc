//! Promises: results that exist before they are ready.
//!
//! A promise is a slot the kernel fills later. Passing one as an argument makes
//! a call *pipelined*: the kernel keeps the dependent call at the provider and
//! dispatches it in the same batch that resolves the promise, so a chain costs
//! one provider round-trip instead of one per step (spec §5).
//!
//! A promise can be resolved once, rejected once, or cancelled; every state
//! transition is checked, and awaiting a cancelled promise is an error rather
//! than a hang.

use std::fmt;

use crate::error::{Error, Result};
use crate::value::Value;

/// Identity of a promise inside one kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PromiseId(pub u64);

impl fmt::Display for PromiseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "p{}", self.0)
    }
}

/// Lifecycle of a promise.
#[derive(Debug, Clone, PartialEq)]
pub enum PromiseState {
    /// Waiting for its producing call.
    Pending,
    /// Resolved with a value.
    Resolved(Value),
    /// Failed; the original error is preserved so the class survives the hop.
    Rejected(crate::error::Error),
    /// Cancelled by the caller; never resolves.
    Cancelled,
}

impl PromiseState {
    /// Whether the promise has resolved, failed or been cancelled.
    pub fn is_settled(&self) -> bool {
        !matches!(self, PromiseState::Pending)
    }
}

/// Provider-side record of one promise.
#[derive(Debug, Clone, PartialEq)]
pub struct PromiseRecord {
    /// Kernel-assigned identifier.
    pub id: PromiseId,
    /// Current state (pending until the producing call settles).
    pub state: PromiseState,
    /// Calls waiting on this promise (derived, informational).
    pub waiters: u32,
    /// Lane that issued the producing call.
    pub lane: u64,
    /// Live [`crate::kernel::PromiseHandle`]s referencing this record.
    ///
    /// A settled record with a live handle is never evicted by retention
    /// trimming: the caller can still read it. `Agent::call` sets this to one
    /// when it returns the handle.
    pub handles: u32,
    /// The peer that queued the producing call, as the transport presented it.
    ///
    /// Dispatch refuses a pipelined argument that names another peer's promise,
    /// so a shared lane cannot become a channel for reading somebody else's
    /// answer (R-11 round 8, F1).
    pub identity: Option<[u8; crate::identity::FINGERPRINT_LEN]>,
}

impl PromiseRecord {
    /// Create a pending record for `id`, owned by `lane`.
    pub fn new(id: PromiseId, lane: u64) -> Self {
        Self {
            id,
            state: PromiseState::Pending,
            waiters: 0,
            lane,
            // No handle owns a reference until `Agent::call` builds one.
            handles: 0,
            identity: None,
        }
    }

    /// Create a pending record that remembers the peer that queued it.
    pub fn new_for(
        id: PromiseId,
        lane: u64,
        identity: Option<[u8; crate::identity::FINGERPRINT_LEN]>,
    ) -> Self {
        Self {
            identity,
            ..Self::new(id, lane)
        }
    }

    /// Resolve once.
    pub fn resolve(&mut self, value: Value) -> Result<()> {
        match self.state {
            PromiseState::Pending => {
                self.state = PromiseState::Resolved(value);
                Ok(())
            }
            // A cancelled promise is not "already resolved": a caller that
            // branches on the code would retry a call the caller cancelled
            // (round 7, #4).
            PromiseState::Cancelled => Err(Error::PromiseCancelled(self.id.0)),
            _ => Err(Error::PromiseAlreadyResolved(self.id.0)),
        }
    }

    /// Reject once.
    pub fn reject(&mut self, error: crate::error::Error) -> Result<()> {
        match self.state {
            PromiseState::Pending => {
                self.state = PromiseState::Rejected(error);
                Ok(())
            }
            PromiseState::Cancelled => Err(Error::PromiseCancelled(self.id.0)),
            _ => Err(Error::PromiseAlreadyResolved(self.id.0)),
        }
    }

    /// Cancel a pending promise.
    pub fn cancel(&mut self) -> Result<()> {
        match self.state {
            PromiseState::Pending => {
                self.state = PromiseState::Cancelled;
                Ok(())
            }
            _ => Err(Error::PromiseAlreadyResolved(self.id.0)),
        }
    }

    /// The settled value, or an error describing why it is not available.
    pub fn value(&self) -> Result<Value> {
        match &self.state {
            PromiseState::Resolved(value) => Ok(value.clone()),
            PromiseState::Pending => Err(Error::UnresolvablePromise(self.id.0)),
            PromiseState::Rejected(error) => Err(error.clone()),
            PromiseState::Cancelled => Err(Error::PromiseCancelled(self.id.0)),
        }
    }
}
