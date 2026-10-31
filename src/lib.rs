//! Active RPC — capability-based, promise-pipelined RPC for Active.
//!
//! Active RPC moves Active Infinity modules and capabilities between agents.
//! It is built around five ideas:
//!
//! 1. **Capabilities, not ambient authority.** A capability is an unforgeable
//!    128-bit id minted by a kernel. Holding it is the only permission needed,
//!    attenuation can only narrow it, and dropping the last handle notifies the
//!    provider.
//! 2. **Promises that pipeline.** A pending result can be passed to another
//!    call, so a chain costs one provider round-trip instead of one per step.
//! 3. **Lanes and channels.** One agent runs many lanes with independent
//!    budgets and speaks on many channels at once, including transfers of
//!    capabilities.
//! 4. **Domain operations.** `evaluate`, `why`, `impact`, `subgraph` and `patch`
//!    operate directly on Infinity modules under the capability's budget.
//! 5. **Transports as adapters.** In-process, shared memory, TCP, QUIC and a
//!    gRPC/Connect bridge carry the same envelope, so capability semantics do
//!    not depend on the wire.
//!
//! # Example
//!
//! ```
//! use active_rpc::cap::CapAttrs;
//! use active_rpc::domain::ModuleProvider;
//! use active_rpc::value::{Arg, Value};
//! use active_rpc::{Agent, Budget};
//!
//! # fn main() -> Result<(), active_rpc::Error> {
//! // A module capability with a call budget.
//! let mut provider = ModuleProvider::new();
//! let object = provider.install(active_rpc::domain::module_from_source(
//!     "port = 8080\n",
//!     "demo.active",
//! )?);
//! let agent = Agent::new();
//! let provider_id = agent.register(Box::new(provider));
//! let cap = agent.mint(provider_id, object, CapAttrs::new(&["stats"]))?;
//! let lane = agent.create_lane("main", Budget::default())?;
//!
//! let promise = agent.call(lane, &cap, "stats", vec![])?;
//! let stats = promise.value()?;
//! assert!(matches!(stats, Value::Map(_)));
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod budget;
pub mod bulk;
pub mod cap;
pub mod channel;
pub mod domain;
pub mod error;
pub mod identity;
pub mod kernel;
pub mod lane;
pub mod observability;
pub mod promise;
pub mod security;
pub mod tool;
pub mod transport;
pub mod value;
pub mod wire;

pub use budget::{Budget, BudgetMeter};
pub use cap::{
    CapAttrs, CapHandle, CapId, CapPersistence, CapRecord, CapToken, ProviderId, ToolPolicy,
};
pub use channel::{Channel, ChannelId, Direction, Message};
pub use error::{Error, Result};
pub use identity::{
    AdmittedIdentity, IdentityKind, IdentityPolicy, PeerIdentity, TrustLevel, FINGERPRINT_LEN,
};
pub use kernel::{Agent, Event, Metrics, PromiseHandle, Provider};
pub use lane::{Lane, LaneId};
pub use promise::{PromiseId, PromiseState};
pub use value::{Arg, Call, Response, Value};
pub use wire::{CapDescriptor, Envelope, Kind, WireLimits};

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Protocol version carried in every envelope.
pub const PROTOCOL_VERSION: u8 = wire::VERSION;

/// Methods every module capability can be granted.
pub const MODULE_METHODS: &[&str] = domain::METHODS;
