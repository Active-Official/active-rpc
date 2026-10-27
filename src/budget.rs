//! Hard resource budgets.
//!
//! Every capability carries a budget, and attenuation can only shrink it. The
//! kernel charges calls, bytes and wall time; domain operations translate the
//! same budget into the Active evaluator's limits, so a call cannot spend more
//! than the caller granted even inside the evaluator.

use crate::error::{Error, Result};

/// A capability's or lane's resource budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// Maximum calls through this capability (and its children in total).
    pub max_calls: u64,
    /// Maximum payload bytes moved through this capability.
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
        ] {
            if value == 0 {
                return Err(Error::InvalidArgument(match name {
                    "max_calls" => "max_calls must be non-zero",
                    "max_bytes" => "max_bytes must be non-zero",
                    "max_wall_ms" => "max_wall_ms must be non-zero",
                    "max_nodes" => "max_nodes must be non-zero",
                    _ => "max_depth must be non-zero",
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

    /// Map onto the Active evaluator's budget. The evaluator gets the same
    /// ceilings, so a capability cannot be used to outspend its grant.
    pub fn to_active_budget(&self) -> active_core::Budget {
        active_core::Budget {
            max_nodes: self.max_nodes,
            max_depth: self.max_depth,
            max_array_len: self.max_array_len,
            max_keys: self.max_depth.saturating_mul(64),
            max_wall_ms: self.max_wall_ms,
            max_value_size: self.max_value_size,
            max_total_value_size: self.max_value_size.saturating_mul(4),
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
    pub fn new(budget: Budget) -> Self {
        Self {
            budget,
            calls: 0,
            bytes: 0,
        }
    }

    pub fn budget(&self) -> &Budget {
        &self.budget
    }

    pub fn calls(&self) -> u64 {
        self.calls
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Remaining call allowance.
    pub fn remaining_calls(&self) -> u64 {
        self.budget.max_calls.saturating_sub(self.calls)
    }

    /// Charge one call and `bytes` of payload.
    pub fn charge(&mut self, bytes: u64) -> Result<()> {
        if self.calls >= self.budget.max_calls {
            return Err(Error::BudgetExceeded("call"));
        }
        if self.bytes.saturating_add(bytes) > self.budget.max_bytes {
            return Err(Error::BudgetExceeded("byte"));
        }
        self.calls += 1;
        self.bytes += bytes;
        Ok(())
    }
}
