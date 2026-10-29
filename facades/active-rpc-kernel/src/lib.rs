//! Kernel facade for `active-rpc`.
//!
//! Re-exports the capability kernel surface: [`Agent`], [`Event`], [`Metrics`],
//! [`PromiseHandle`] and [`Provider`], plus the budget, capability and error
//! types needed to drive them.

pub use active_rpc::kernel::{Agent, Event, Metrics, PromiseHandle, Provider};
pub use active_rpc::{
    Budget, CapAttrs, CapHandle, CapId, CapToken, Error, LaneId, ProviderId, Result, ToolPolicy,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_facade_exposes_a_real_agent() {
        let agent = Agent::new();
        assert_eq!(agent.metrics().calls_queued, 0);
        assert_eq!(agent.promise_count(), 0);
    }
}
