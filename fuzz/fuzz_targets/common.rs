//! Shared helpers for the Active RPC fuzz targets.
//!
//! Only the public API is used. The provider is deterministic so a failure is
//! replayable from the input bytes alone.

#![allow(dead_code)]

use active_rpc::error::Result;
use active_rpc::value::Call;
use active_rpc::{
    Agent, Budget, CapAttrs, CapId, PromiseHandle, Provider, ProviderId, Response, Value,
};

/// A deterministic provider. It records drop notifications so a target can
/// assert the last-handle rule.
#[derive(Default)]
pub struct Echo {
    drops: Vec<(u64, CapId)>,
}

impl Provider for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn methods(&self) -> Vec<String> {
        ["echo", "ping", "fail"]
            .iter()
            .map(|name| name.to_string())
            .collect()
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, call: &Call) -> Result<Response> {
        if call.method == "fail" {
            return Err(active_rpc::Error::Provider {
                code: "fuzz/fail".into(),
            });
        }
        Ok(Response::Value(Value::text("pong")))
    }

    fn on_drop(&mut self, object: u64, cap: CapId) {
        self.drops.push((object, cap));
    }

    fn take_drop_notifications(&mut self) -> Vec<(u64, CapId)> {
        std::mem::take(&mut self.drops)
    }
}

/// Expand a fuzz seed into a kernel secret by cycling it.
///
/// Exposed so a target that needs a *different* kernel can perturb the seed and
/// be sure the secret differs: `data` and `data` with byte 0 flipped can never
/// produce the same secret, while an unrelated seed may (a seed of all `0x06`
/// expands to exactly the same 32 bytes as a one-byte seed of `0x06`).
pub fn secret(seed: &[u8]) -> [u8; 32] {
    let mut secret = [0u8; 32];
    for (slot, byte) in secret.iter_mut().zip(seed.iter().cycle()) {
        *slot = *byte;
    }
    secret
}

pub fn agent(seed: &[u8]) -> Agent {
    Agent::with_secret(secret(seed))
}

pub fn methods(data: &[u8]) -> Vec<&'static str> {
    let all = ["ping", "echo", "fail"];
    let count = 1 + data.first().copied().unwrap_or(0) as usize % all.len();
    all[..count].to_vec()
}

pub fn mint(
    agent: &Agent,
    provider: ProviderId,
    methods: &[&str],
    budget: Budget,
) -> active_rpc::CapHandle {
    let attrs = CapAttrs::new(methods).with_budget(budget);
    agent
        .mint(provider, 0, attrs)
        .expect("the fuzz harness mints a valid capability")
}

pub fn settle(promise: &PromiseHandle) -> Option<Value> {
    promise.value().ok()
}

pub fn budget_from(data: &[u8]) -> Budget {
    let byte = |index: usize| data.get(index).copied().unwrap_or(1) as u64;
    Budget {
        max_calls: 1 + byte(0) % 16,
        max_bytes: 1 + byte(1) % 4096,
        max_wall_ms: 1 + byte(2) % 100,
        max_nodes: 1 + byte(3) % 1024,
        max_depth: 1 + byte(4) % 32,
        max_array_len: 1 + byte(5) % 64,
        max_value_size: 1 + byte(6) % 4096,
    }
}
