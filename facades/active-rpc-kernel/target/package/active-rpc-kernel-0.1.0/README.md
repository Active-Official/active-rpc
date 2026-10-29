# active-rpc-kernel

The capability kernel surface: agents, events, metrics, promises and providers.

This crate is a thin, versioned facade over [`active-rpc`](https://crates.io/crates/active-rpc).
The implementation lives in the parent crate; this package keeps the module
name stable for downstream users and protects the namespace for the project.

- Repository: <https://github.com/Active-Official/active-rpc>
- Main crate: <https://crates.io/crates/active-rpc>
- License: MIT OR Apache-2.0

```toml
[dependencies]
active-rpc-kernel = "0.1"
```
