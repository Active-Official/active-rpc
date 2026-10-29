//! Client facade for `active-rpc`.
//!
//! The agent is the client: [`Agent`] mints capabilities, queues calls and
//! returns [`PromiseHandle`] values that settle in dependency order.

pub use active_rpc::kernel::{Agent, PromiseHandle};
pub use active_rpc::value::{Arg, Call, Response, Value};
pub use active_rpc::{Error, Result};
