# Registry baseline — Active Infinity / Active RPC

Recorded: 2026-10-29 for AIM-PROP-2026-10 C-0.4.

| Crate | Published | Owner on crates.io | Strategy |
|---|---|---|---|
| `active-infinity` | 2.1.0 | `RatioArtificiosa` | reference codec; semver 2.x |
| `active-rpc` | 2.0.0 | `RatioArtificiosa` | reference RPC kernel; semver 2.x |
| `active-infinity-cli` | 0.1.0 | `RatioArtificiosa` | CLI product for Infinity; 0.x until CLI surface stabilizes |
| `active-rpc-cli` | 0.1.0 | `RatioArtificiosa` | CLI product for RPC; 0.x until CLI surface stabilizes |
| `active-infinity-core` | 0.1.1 | `RatioArtificiosa` | module facade |
| `active-infinity-stream` | 0.1.1 | `RatioArtificiosa` | module facade |
| `active-infinity-interop` | 0.1.1 | `RatioArtificiosa` | module facade |
| `active-infinity-wasm` | 0.1.1 | `RatioArtificiosa` | reserved binding name |
| `active-rpc-kernel` | 0.1.1 | `RatioArtificiosa` | module facade |
| `active-rpc-core` | 0.1.1 | `RatioArtificiosa` | module facade |
| `active-rpc-client` | 0.1.1 | `RatioArtificiosa` | module facade |
| `active-rpc-tools` | 0.1.1 | `RatioArtificiosa` | module facade |
| `active-rpc-transport` | 0.1.1 | `RatioArtificiosa` | module facade |

Rules:

- Library crates follow semver; wire identity changes require an ADR and a
  major/minor decision in the same release.
- CLI crates stay 0.x while flags and scorecard JSON may move; breaking CLI
  changes still bump the minor.
- Every publish is from a clean commit, with `cargo publish --dry-run` and the
  dual-remote tag recorded in `docs/hardening/RELEASE.md`.
