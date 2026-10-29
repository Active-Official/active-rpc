# Active RPC crate family

The published crates keep the kernel, transport, tools and client names with the
project. Facade sources live in `facades/` and are excluded from the main
`active-rpc` package tarball.

| Crate | Version | Purpose |
|---|---|---|
| [`active-rpc`](https://crates.io/crates/active-rpc) | 2.0.0 | Capability-based, promise-pipelined RPC kernel |
| [`active-rpc-kernel`](https://crates.io/crates/active-rpc-kernel) | 0.1.0 | Agent, events, metrics, promises and providers |
| [`active-rpc-core`](https://crates.io/crates/active-rpc-core) | 0.1.0 | Capability, budget, value and wire types |
| [`active-rpc-client`](https://crates.io/crates/active-rpc-client) | 0.1.0 | Agent, call and promise client surface |
| [`active-rpc-tools`](https://crates.io/crates/active-rpc-tools) | 0.1.0 | MCP, HTTP and sandboxed local-process adapters |
| [`active-rpc-transport`](https://crates.io/crates/active-rpc-transport) | 0.1.0 | In-process, TCP, shared-memory and QUIC transports |
| [`active-rpc-cli`](https://crates.io/crates/active-rpc-cli) | 0.1.0 | Reserved CLI name |

Each facade is a thin, versioned re-export of the shipped module. The main
crate remains the implementation and the source of truth.

Python and JavaScript registries are intentionally not reserved while these
are Rust-only libraries. Empty npm or PyPI packages would misrepresent the API;
the crates above are the supported distribution channel.
