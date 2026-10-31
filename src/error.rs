//! Stable, machine-readable errors for Active RPC.
//!
//! Codes are permanent (`rpc/…`) and are part of the wire contract: peers
//! branch on codes, never on messages, and a message never echoes payload,
//! argument or secret material.

use std::fmt;

/// Result alias for every fallible operation in this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// A capability, promise, transport or protocol failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A capability id is unknown to this kernel (forged or expired).
    UnknownCapability(crate::cap::CapToken),
    /// A capability exists but the requested method is outside its grants.
    MethodNotGranted {
        /// Method that was attempted.
        method: String,
    },
    /// An attenuation attempt would widen authority.
    Escalation(&'static str),
    /// A capability is read-only and the call mutates state.
    ReadOnly,
    /// A path restriction rejected the call.
    PathNotGranted(String),
    /// A tool policy rejected the call.
    ToolPolicy(&'static str),
    /// The capability has been revoked or its provider disappeared.
    Revoked(crate::cap::CapToken),
    /// A budget was exhausted.
    BudgetExceeded(&'static str),
    /// The lane does not exist (or was destroyed).
    UnknownLane(u64),
    /// The channel does not exist.
    UnknownChannel(u64),
    /// The promise does not exist.
    UnknownPromise(u64),
    /// A promise was cancelled and can no longer be awaited.
    PromiseCancelled(u64),
    /// A promise was resolved twice.
    PromiseAlreadyResolved(u64),
    /// The local queue or channel window is full; retry after the peer drains.
    Backpressure(&'static str),
    /// The peer's authenticated identity is missing or does not match the
    /// capability's binding.
    Identity(&'static str),
    /// A bulk-transfer plan or chunk is malformed, truncated or fails its hash.
    Bulk(&'static str),
    /// The call references a promise that will never resolve.
    UnresolvablePromise(u64),
    /// The provider failed the call.
    Provider {
        /// Stable provider-side code.
        code: String,
    },
    /// A translated Active evaluation failed.
    Domain(&'static str),
    /// A payload is not a valid Active Infinity module.
    Payload(String),
    /// The wire envelope is malformed.
    Wire(&'static str),
    /// The envelope's capability table is malformed or oversized.
    CapabilityTable(&'static str),
    /// A transport failed.
    Transport(String),
    /// A transport is unavailable in this build or on this host.
    TransportUnavailable(&'static str),
    /// A deadline elapsed before the call completed.
    Timeout,
    /// The kernel detected a cycle in pipelined calls.
    PipelinedCycle,
    /// Invalid argument supplied by the caller.
    InvalidArgument(&'static str),
}

impl Error {
    /// Permanent machine-readable code.
    pub const fn code(&self) -> &'static str {
        match self {
            Error::UnknownCapability(_) => "rpc/unknown-capability",
            Error::MethodNotGranted { .. } => "rpc/method-not-granted",
            Error::Escalation(_) => "rpc/attenuation-escalation",
            Error::ReadOnly => "rpc/read-only",
            Error::PathNotGranted(_) => "rpc/path-not-granted",
            Error::ToolPolicy(_) => "rpc/tool-policy",
            Error::Revoked(_) => "rpc/revoked",
            Error::BudgetExceeded(_) => "rpc/budget-exceeded",
            Error::UnknownLane(_) => "rpc/unknown-lane",
            Error::UnknownChannel(_) => "rpc/unknown-channel",
            Error::UnknownPromise(_) => "rpc/unknown-promise",
            Error::PromiseCancelled(_) => "rpc/promise-cancelled",
            Error::PromiseAlreadyResolved(_) => "rpc/promise-resolved",
            Error::Backpressure(_) => "rpc/backpressure",
            Error::Identity(_) => "rpc/identity",
            Error::Bulk(_) => "rpc/bulk",
            Error::UnresolvablePromise(_) => "rpc/unresolvable-promise",
            Error::Provider { .. } => "rpc/provider",
            Error::Domain(_) => "rpc/domain",
            Error::Payload(_) => "rpc/payload",
            Error::Wire(_) => "rpc/wire",
            Error::CapabilityTable(_) => "rpc/capability-table",
            Error::Transport(_) => "rpc/transport",
            Error::TransportUnavailable(_) => "rpc/transport-unavailable",
            Error::Timeout => "rpc/timeout",
            Error::PipelinedCycle => "rpc/pipelined-cycle",
            Error::InvalidArgument(_) => "rpc/invalid-argument",
        }
    }

    /// True when the failure means the peer sent something hostile.
    pub const fn is_fatal(&self) -> bool {
        matches!(
            self,
            Error::Wire(_)
                | Error::CapabilityTable(_)
                | Error::Payload(_)
                | Error::UnknownCapability(_)
        )
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnknownCapability(id) => write!(f, "unknown capability {id}"),
            Error::MethodNotGranted { method } => write!(f, "method {method} is not granted"),
            Error::Escalation(what) => write!(f, "attenuation would widen authority: {what}"),
            Error::ReadOnly => write!(f, "capability is read-only"),
            Error::PathNotGranted(path) => write!(f, "path {path} is outside the capability"),
            Error::ToolPolicy(what) => write!(f, "tool policy rejects the call: {what}"),
            Error::Revoked(id) => write!(f, "capability {id} is revoked"),
            Error::BudgetExceeded(kind) => write!(f, "{kind} budget exhausted"),
            Error::UnknownLane(id) => write!(f, "unknown lane {id}"),
            Error::UnknownChannel(id) => write!(f, "unknown channel {id}"),
            Error::UnknownPromise(id) => write!(f, "unknown promise {id}"),
            Error::PromiseCancelled(id) => write!(f, "promise {id} was cancelled"),
            Error::PromiseAlreadyResolved(id) => write!(f, "promise {id} was already resolved"),
            Error::Backpressure(what) => write!(f, "backpressure: {what}"),
            Error::Identity(what) => write!(f, "peer identity refused: {what}"),
            Error::Bulk(what) => write!(f, "bulk transfer rejected: {what}"),
            Error::UnresolvablePromise(id) => write!(f, "promise {id} can never resolve"),
            Error::Provider { code } => write!(f, "provider failed: {code}"),
            Error::Domain(code) => write!(f, "domain operation failed: {code}"),
            Error::Payload(reason) => write!(f, "invalid payload: {reason}"),
            Error::Wire(reason) => write!(f, "malformed envelope: {reason}"),
            Error::CapabilityTable(reason) => write!(f, "malformed capability table: {reason}"),
            Error::Transport(reason) => write!(f, "transport failure: {reason}"),
            Error::TransportUnavailable(name) => write!(f, "transport {name} is unavailable"),
            Error::Timeout => write!(f, "deadline elapsed"),
            Error::PipelinedCycle => write!(f, "pipelined calls form a cycle"),
            Error::InvalidArgument(what) => write!(f, "invalid argument: {what}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<active_infinity::Error> for Error {
    fn from(error: active_infinity::Error) -> Self {
        Error::Payload(error.code().to_string())
    }
}
