//! Kernel facade for `active-rpc`.
//!
//! Re-exports the capability kernel surface: [`Agent`], [`Event`], [`Metrics`],
//! [`PromiseHandle`] and [`Provider`], plus the budget, capability and error
//! types needed to drive them.

pub use active_rpc::kernel::{Agent, Event, Metrics, PromiseHandle, Provider};
pub use active_rpc::{
    Budget, CapAttrs, CapHandle, CapId, CapToken, Error, LaneId, ProviderId, Result, ToolPolicy,
};
