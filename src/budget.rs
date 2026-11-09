//! Hard resource budgets.
//!
//! Every capability carries a budget, and attenuation can only shrink it. The
//! kernel charges calls and bytes: the request when the call is queued, the
//! resolved arguments when a promise grows at dispatch, and the response before
//! it is delivered. `max_wall_ms` is enforced by the adapters that can measure
//! time (`LocalProcess` today). Domain operations translate the same budget into
//! the Active evaluator's limits, so a call cannot spend more than the caller
//! granted even inside the evaluator.

use crate::error::{Error, Result};

/// A capability's or lane's resource budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// Maximum calls through this capability (and its children in total).
    pub max_calls: u64,
    /// Maximum payload bytes moved through this capability, in both
    /// directions: arguments, the method name, capability descriptors and
    /// table deltas, envelope payload and the response the provider
    /// returns. The descriptor half is charged at queue time from the
    /// envelope (RPC-52); without it a peer could move a descriptor table
    /// past a meter that only counted arguments.
    pub max_bytes: u64,
    /// Maximum wall-clock milliseconds for one call.
    pub max_wall_ms: u64,
    /// Maximum Active IR nodes an evaluation may visit.
    pub max_nodes: u64,
    /// Maximum value nesting depth.
    pub max_depth: u64,
    /// Maximum array length.
    pub max_array_len: u64,
    /// Maximum materialised value size.
    pub max_value_size: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            max_calls: 10_000,
            max_bytes: 64 << 20,
            max_wall_ms: 5_000,
            max_nodes: 100_000,
            max_depth: 256,
            max_array_len: 100_000,
            max_value_size: 10_000_000,
        }
    }
}

impl Budget {
    /// A tight profile for adversarial tests.
    pub fn strict() -> Self {
        Self {
            max_calls: 64,
            max_bytes: 1 << 20,
            max_wall_ms: 100,
            max_nodes: 4_096,
            max_depth: 64,
            max_array_len: 1_024,
            max_value_size: 1 << 20,
        }
    }

    /// A small budget with a fixed call allowance, for attenuation tests.
    pub fn calls(limit: u64) -> Self {
        Self {
            max_calls: limit,
            ..Budget::default()
        }
    }

    /// Reject a budget that would disable a ceiling.
    pub fn check(&self) -> Result<()> {
        for (name, value) in [
            ("max_calls", self.max_calls),
            ("max_bytes", self.max_bytes),
            ("max_wall_ms", self.max_wall_ms),
            ("max_nodes", self.max_nodes),
            ("max_depth", self.max_depth),
            ("max_array_len", self.max_array_len),
            ("max_value_size", self.max_value_size),
        ] {
            if value == 0 {
                return Err(Error::InvalidArgument(match name {
                    "max_calls" => "max_calls must be non-zero",
                    "max_bytes" => "max_bytes must be non-zero",
                    "max_wall_ms" => "max_wall_ms must be non-zero",
                    "max_nodes" => "max_nodes must be non-zero",
                    "max_depth" => "max_depth must be non-zero",
                    "max_array_len" => "max_array_len must be non-zero",
                    _ => "max_value_size must be non-zero",
                }));
            }
        }
        Ok(())
    }

    /// True when every ceiling of `self` is at most `parent`'s.
    pub fn is_attenuation_of(&self, parent: &Budget) -> bool {
        self.max_calls <= parent.max_calls
            && self.max_bytes <= parent.max_bytes
            && self.max_wall_ms <= parent.max_wall_ms
            && self.max_nodes <= parent.max_nodes
            && self.max_depth <= parent.max_depth
            && self.max_array_len <= parent.max_array_len
            && self.max_value_size <= parent.max_value_size
    }

    /// Pointwise minimum: the strongest attenuation of two budgets.
    pub fn intersect(&self, other: &Budget) -> Budget {
        Budget {
            max_calls: self.max_calls.min(other.max_calls),
            max_bytes: self.max_bytes.min(other.max_bytes),
            max_wall_ms: self.max_wall_ms.min(other.max_wall_ms),
            max_nodes: self.max_nodes.min(other.max_nodes),
            max_depth: self.max_depth.min(other.max_depth),
            max_array_len: self.max_array_len.min(other.max_array_len),
            max_value_size: self.max_value_size.min(other.max_value_size),
        }
    }

    /// Map onto the Active evaluator's budget.
    ///
    /// The evaluator's ceilings never exceed the grant: a capability cannot be
    /// used to outspend the bytes it was given just because its per-value
    /// ceiling is larger. `max_keys` and `max_total_value_size` are derived
    /// from the grant and then clamped to it.
    pub fn to_active_budget(&self) -> active_core::Budget {
        active_core::Budget {
            max_nodes: self.max_nodes,
            max_depth: self.max_depth,
            max_array_len: self.max_array_len,
            max_keys: self.max_array_len.min(self.max_depth.saturating_mul(64)),
            max_wall_ms: self.max_wall_ms,
            max_value_size: self.max_value_size,
            max_total_value_size: self.max_value_size.min(self.max_bytes),
        }
    }
}

/// Mutable charge counter attached to one capability use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetMeter {
    budget: Budget,
    calls: u64,
    bytes: u64,
}

impl BudgetMeter {
    /// Start a meter at zero usage against `budget`.
    pub fn new(budget: Budget) -> Self {
        Self {
            budget,
            calls: 0,
            bytes: 0,
        }
    }

    /// The ceiling this meter enforces.
    pub fn budget(&self) -> &Budget {
        &self.budget
    }

    /// Remaining byte allowance.
    pub fn remaining_bytes(&self) -> u64 {
        self.budget.max_bytes.saturating_sub(self.bytes)
    }

    /// Refuse unless `calls` and `bytes` more fit under both ceilings.
    ///
    /// Used by an export, which transfers a grant out of the meters that hold it
    /// rather than charging a call.
    pub fn check_reserve(&self, calls: u64, bytes: u64) -> Result<()> {
        let total_calls = self
            .calls
            .checked_add(calls)
            .ok_or(Error::BudgetExceeded("call"))?;
        if total_calls > self.budget.max_calls {
            return Err(Error::BudgetExceeded("call"));
        }
        let total_bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or(Error::BudgetExceeded("byte"))?;
        if total_bytes > self.budget.max_bytes {
            return Err(Error::BudgetExceeded("byte"));
        }
        Ok(())
    }

    /// Reserve `calls` and `bytes` without consuming the current call counter's
    /// meaning: the grant has moved out, it was not spent here.
    pub fn reserve(&mut self, calls: u64, bytes: u64) -> Result<()> {
        self.check_reserve(calls, bytes)?;
        self.calls = self.calls.saturating_add(calls);
        self.bytes = self.bytes.saturating_add(bytes);
        Ok(())
    }

    /// Calls charged so far.
    pub fn calls(&self) -> u64 {
        self.calls
    }

    /// Payload bytes charged so far.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Remaining call allowance.
    pub fn remaining_calls(&self) -> u64 {
        self.budget.max_calls.saturating_sub(self.calls)
    }

    /// Refuse unless one more call of `bytes` fits under every ceiling.
    ///
    /// Kept separate from [`BudgetMeter::charge`] so a caller that charges a
    /// chain of meters (a capability and its ancestors) can check them all
    /// before charging any: a refused call must not consume part of a grant.
    /// Arithmetic is checked, so a hostile byte count cannot wrap the counter
    /// and quietly disable the ceiling.
    pub fn check(&self, bytes: u64) -> Result<()> {
        if self.calls >= self.budget.max_calls {
            return Err(Error::BudgetExceeded("call"));
        }
        let total = self
            .bytes
            .checked_add(bytes)
            .ok_or(Error::BudgetExceeded("byte"))?;
        if total > self.budget.max_bytes {
            return Err(Error::BudgetExceeded("byte"));
        }
        Ok(())
    }

    /// Refuse unless `bytes` more fit under the byte ceiling.
    ///
    /// Used when an already-charged call grows at dispatch: the extra bytes are
    /// checked against every meter in the chain before any of them is charged.
    pub fn check_bytes(&self, bytes: u64) -> Result<()> {
        if bytes == 0 {
            return Ok(());
        }
        let total = self
            .bytes
            .checked_add(bytes)
            .ok_or(Error::BudgetExceeded("byte"))?;
        if total > self.budget.max_bytes {
            return Err(Error::BudgetExceeded("byte"));
        }
        Ok(())
    }

    /// Charge bytes without consuming a call.
    ///
    /// Used when a queued argument grew at dispatch: a promise that resolved to
    /// a larger value than its placeholder still has to be paid for.
    pub fn charge_bytes(&mut self, bytes: u64) -> Result<()> {
        if bytes == 0 {
            return Ok(());
        }
        self.check_bytes(bytes)?;
        self.bytes = self.bytes.saturating_add(bytes);
        Ok(())
    }

    /// Charge one call and `bytes` of payload.
    pub fn charge(&mut self, bytes: u64) -> Result<()> {
        self.check(bytes)?;
        self.calls = self.calls.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
        Ok(())
    }
}
