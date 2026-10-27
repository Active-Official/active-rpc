# Active RPC

**Capability-based, promise-pipelined RPC for Active Infinity and multi-agent
systems.** gRPC is a transport; Active RPC is a security and execution model with
a transport attached.

```text
cap ──► call ──► promise ──► pipelined call ──► result
 │                    │
 └── attenuation ─────┴── lanes / channels / tools
```

## Why it exists

An agent that calls tools and other agents needs four things that a
request/response RPC does not give it:

1. **No ambient authority.** A capability is an unforgeable id minted by the
   receiving kernel; holding it is the whole permission, attenuation can only
   narrow it, and revocation is immediate and transitive.
2. **Pipelining.** A pending result can be an argument to the next call, so a
   chain costs one provider round-trip instead of one per step. Measured, not
   asserted: see `tests/unit_tests.rs::pipelining_costs_one_round_trip…`.
3. **Concurrency primitives.** Many lanes with independent budgets, many named
   channels, capability transfer over channels, and many tool handles in flight.
4. **Domain operations.** `evaluate`, `why`, `impact`, `subgraph` and `patch` run
   on Active Infinity modules under the capability's budget, not on JSON.

## Quick start

```rust
use active_rpc::cap::CapAttrs;
use active_rpc::domain::ModuleProvider;
use active_rpc::value::{Arg, Value};
use active_rpc::{Agent, Budget};

# fn main() -> Result<(), active_rpc::Error> {
let mut provider = ModuleProvider::new();
let object = provider.install(active_rpc::domain::module_from_source(
    "[server]\nport = 8080\n", "demo.active")?);
let agent = Agent::new();
let provider_id = agent.register(Box::new(provider));

let cap = agent.mint(provider_id, object, CapAttrs::new(&["evaluate", "why"]))?;
let lane = agent.create_lane("main", Budget::default())?;

let promise = agent.call(lane, &cap, "evaluate", vec![
    Arg::Value(Value::Path("server".into())),
])?;
assert!(matches!(promise.value()?, Value::Map(_)));
# Ok(())
# }
```

Pipelining:

```rust
# use active_rpc::{Agent, Budget, CapAttrs};
# use active_rpc::value::{Arg, Value};
# use active_rpc::domain::ModuleProvider;
# fn main() -> Result<(), active_rpc::Error> {
# let mut provider = ModuleProvider::new();
# let object = provider.install(active_rpc::domain::module_from_source("[a]\nb = 1\n", "x")?);
# let agent = Agent::new();
# let id = agent.register(Box::new(provider));
# let cap = agent.mint(id, object, CapAttrs::new(&["stats"]))?;
# let lane = agent.create_lane("main", Budget::default())?;
// The second call names the first result; both dispatch in one batch.
let first = agent.call(lane, &cap, "stats", vec![])?;
let second = agent.call(lane, &cap, "stats", vec![Arg::Promise(first.id())])?;
let _ = second.value()?;
assert_eq!(agent.round_trips(), 1);
# Ok(())
# }
```

## Architecture

| Module | Responsibility |
|--------|----------------|
| `kernel` | capability table, promise graph, lane/channel registry, dispatch loop, events |
| `cap` | ids, attributes, attenuation rules, handles with drop notification |
| `promise` | promise states and single-settlement rules |
| `lane` / `channel` | execution contexts and named streams with capability transfer |
| `domain` | `evaluate`/`why`/`impact`/`subgraph`/`patch` over Infinity modules |
| `tool` | MCP, HTTP/OpenAPI and sandboxed local-process adapters |
| `wire` | the `ARP1` envelope and capability table |
| `transport` | in-process, TCP, shared memory, QUIC, gRPC/Connect bridge |
| `security` | redaction and value mapping |

The kernel is a deterministic state machine: providers are plain objects, the
clock is a counter, and `Agent::run()` drives dispatch. That is why pipelining,
attenuation, budget exhaustion and drop notification are testable without timing
flakes — and why a transport is a thin adapter (ADR-0002).

## Feature flags

| Feature | Default | Meaning |
|---|---|---|
| `quic` | on | real QUIC transport (quinn + rustls, self-signed, loopback) |

`--no-default-features` builds every transport except QUIC (in-process, TCP,
shared memory, Connect bridge).

## Testing

```bash
cargo test                 # unit, integration, concurrency, conformance, red team, property
cargo test --no-default-features
cargo bench                # wire, transports, kernel call loop
```

The suite proves, among other things: a forged capability is refused; attenuation
cannot widen; a dropped handle notifies the provider; a pipelined chain costs one
round-trip where a sequential chain costs two; each transport moves a real
Infinity payload plus a capability table and rejects a malformed frame; two agents
do not cross-talk over TCP; and secret material never appears in any value,
envelope, annotation or provenance path.

## Specifications

- [`docs/spec/wire.md`](docs/spec/wire.md) — normative envelope, capability table, error codes
- [`docs/spec/security.md`](docs/spec/security.md) — threat model
- [`docs/spec/performance.md`](docs/spec/performance.md) — baselines
- [`docs/adr/`](docs/adr/README.md) — architecture decisions

## License

MIT OR Apache-2.0.
