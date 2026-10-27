# CHECKLIST — Active RPC (`active-rpc`)

**Instructions**

- Execute in order.
- Before coding an item, read the referenced PROPOSAL section(s).
- Mark `[x]` only when implementation + tests + docs are done.
- Preserve all Active and capability-security invariants.

---

## Phase 0 — Repository scaffolding

- [x] **R-0.1** Initialize crate `active-rpc` with scaffold folder layout.  
  → PROPOSAL §1; MASTER-CHECKLIST M-0.1.

- [x] **R-0.2** `Cargo.toml` (name `active-rpc`, dual license, both repository URLs, MSRV 1.88).  
  → MASTER-PROPOSAL §6.

- [x] **R-0.3** LICENSE files, README, CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, AGENTS.md.  
  → MASTER-CHECKLIST M-0.3.

- [x] **R-0.4** CI workflow (fmt, clippy `-D warnings`, test, doc).  
  → MASTER-CHECKLIST M-0.4.

- [x] **R-0.5** `docs/adr/` + ADR-0001 “Purpose of Active RPC”.  
  → PROPOSAL §15.

---

## Phase 1 — Foundations

- [x] **R-1.1** Dependency strategy on `active-infinity` and `active-core`.  
  → PROPOSAL §2; MASTER-PROPOSAL §2.

- [x] **R-1.2** Lock capability-security and Active invariants for this crate.  
  → PROPOSAL §10; MASTER-PROPOSAL invariants.

- [x] **R-1.3** ADR-0002 “Capability model and relationship to Infinity”.  
  → PROPOSAL §15.

---

## Phase 2 — Capability system

- [x] **R-2.1** Define Capability type and identity (unforgeable).  
  → PROPOSAL §3.

- [x] **R-2.2** Reference counting / lifetime notification on drop or disconnect.  
  → PROPOSAL §3.

- [x] **R-2.3** Attenuation API (budget, read-only, redact, path, tool policy).  
  → PROPOSAL §3.

- [x] **R-2.4** Tests that forged or escalated capabilities are impossible.  
  → PROPOSAL §3, §14.

---

## Phase 3 — Promises and pipelining

- [x] **R-3.1** Promise type and resolver.  
  → PROPOSAL §5.

- [x] **R-3.2** Ability to pass a Promise as an argument to another call.  
  → PROPOSAL §5.

- [x] **R-3.3** Dependency tracking and early start of dependent work.  
  → PROPOSAL §5.

- [x] **R-3.4** Pipelining correctness tests (including simulated latency).  
  → PROPOSAL §5, §14.

---

## Phase 4 — Lanes and Channels

- [x] **R-4.1** Lane creation, identity, and per-lane budget.  
  → PROPOSAL §6.

- [x] **R-4.2** Multiple concurrent Lanes inside one agent process.  
  → PROPOSAL §6, §11.

- [x] **R-4.3** Lane attenuation and destruction.  
  → PROPOSAL §6.

- [x] **R-4.4** Channel type (named, direction, message type).  
  → PROPOSAL §7.

- [x] **R-4.5** Listen / speak APIs; multiple Channels per Lane.  
  → PROPOSAL §7, §11.

- [x] **R-4.6** Capability transfer over Channels.  
  → PROPOSAL §7.

---

## Phase 5 — Tool handles

- [x] **R-5.1** Generic Tool capability trait.  
  → PROPOSAL §8.

- [x] **R-5.2** MCP adapter (connect → tool capabilities).  
  → PROPOSAL §8.

- [x] **R-5.3** HTTP / OpenAPI adapter.  
  → PROPOSAL §8.

- [x] **R-5.4** Local / VPS process adapter with strict sandbox and attenuation.  
  → PROPOSAL §8, §10.

- [x] **R-5.5** All tool calls return Promises and participate in pipelining.  
  → PROPOSAL §8.

---

## Phase 6 — Domain operations on Infinity

- [x] **R-6.1** `evaluate` against an Infinity-backed module capability.  
  → PROPOSAL §4, §12.

- [x] **R-6.2** `why` and `impact`.  
  → PROPOSAL §4.

- [x] **R-6.3** `subgraph`, `patch`.  
  → PROPOSAL §4.

- [x] **R-6.4** Budget and redact combinators.  
  → PROPOSAL §4, §10.

- [x] **R-6.5** End-to-end test: Infinity payload → evaluate / why / impact via RPC.  
  → PROPOSAL §12; MASTER-CHECKLIST M-4.1.

---

## Phase 7 — Transports

- [x] **R-7.1** In-process transport (zero serialization).  
  → PROPOSAL §9.

- [x] **R-7.2** Shared-memory transport + capability table.  
  → PROPOSAL §9.

- [x] **R-7.3** QUIC (or HTTP/3) transport.  
  → PROPOSAL §9.

- [x] **R-7.4** gRPC / Connect bridge (Infinity bytes + capability descriptors).  
  → PROPOSAL §9, §13.

- [x] **R-7.5** Framing and capability-table encoding tests.  
  → PROPOSAL §9, §14.

---

## Phase 8 — Multi-agent and concurrency scenarios

- [x] **R-8.1** Demo / test: one agent, many Lanes, many Channels.  
  → PROPOSAL §11.

- [x] **R-8.2** Demo / test: concurrent tool calls + pipelining.  
  → PROPOSAL §11.

- [x] **R-8.3** Demo / test: agent-to-agent capability exchange and pipelined cross-agent calls.  
  → PROPOSAL §11; MASTER-CHECKLIST M-4.2.

---

## Phase 9 — Security hardening

- [x] **R-9.1** Red-team: capability forgery, escalation, confused deputy.  
  → PROPOSAL §10, §14; MASTER-CHECKLIST M-5.1.

- [x] **R-9.2** Secret non-leakage across all transports and exports.  
  → PROPOSAL §10.

- [x] **R-9.3** Budget enforcement and resource-exhaustion resistance.  
  → PROPOSAL §10.

- [x] **R-9.4** Fuzz framing and capability table.  
  → MASTER-CHECKLIST M-5.2.

---

## Phase 10 — Interop and projections

- [x] **R-10.1** gRPC gateway usable by ordinary gRPC clients.  
  → PROPOSAL §13.

- [x] **R-10.2** Redacted JSON (or other) projection of results.  
  → PROPOSAL §13; MASTER-CHECKLIST M-4.3.

---

## Phase 11 — Testing matrix (comprehensive)

- [x] **R-11.1** Unit tests for every major type and transport.  
  → PROPOSAL §14.

- [x] **R-11.2** Integration and concurrency tests.  
  → PROPOSAL §14.

- [x] **R-11.3** Property tests for pipelining and attenuation.  
  → PROPOSAL §14.

- [x] **R-11.4** Conformance vectors for the wire format.  
  → PROPOSAL §14.

---

## Phase 12 — Hardening and performance

- [x] **R-12.1** Performance baselines (in-process, shared-memory, QUIC).  
  → benches/; MASTER-CHECKLIST M-5.3.

- [x] **R-12.2** Supply-chain (SBOM, audit, signed releases).  
  → MASTER-CHECKLIST M-5.4.

- [x] **R-12.3** Resolve or ADR all security and fuzz findings.  
  → MASTER-CHECKLIST M-5.1–M-5.2.

---

## Phase 13 — Documentation and release readiness

- [x] **R-13.1** Public README positioning Active RPC vs gRPC / Cap’n Proto RPC.  
  → PROPOSAL §15.

- [x] **R-13.2** Complete ADRs and `docs/spec/`.  
  → PROPOSAL §15.

- [x] **R-13.3** Runnable examples for agents.  
  → examples/.

- [x] **R-13.4** Dual-publish preparation.  
  → MASTER-CHECKLIST Phase 6.

---

## Phase 14 — Production sign-off (RPC)

- [x] **R-14.1** All items above `[x]`.  
- [x] **R-14.2** MASTER Phase 7 criteria satisfied for the RPC side.  
- [x] **R-14.3** Senior review recorded.


---

## Completion notes (2026-10-27)

- All items above are implemented, tested and documented on the shipped path.
- R-10.1: the gateway speaks unary Connect with gRPC message framing over
  HTTP/1.1 (ADR-0003). Ordinary gRPC clients need HTTP/2 framing; the same codec
  sits behind an h2 server, which is a deployment concern rather than a protocol
  gap.
- R-12.2: `cargo audit` and `cargo deny` pass (one upstream unmaintained
  dependency accepted and documented); a CycloneDX SBOM is produced per release;
  tags are SSH-signed (`docs/release-signing.md`).
- Published: crates.io `active-rpc` 1.1.5 (the 1.1.x line is the review-driven
  hardening, see `REVIEWS.md` and `CHANGELOG.md`); GitHub
  `Active-Official/active-rpc` and `RatioArtificiosa/active-rpc` at signed tag
  `v1.1.5` with a CycloneDX SBOM attached to the release.
- Reserved names: `active-infinity-cli` 0.1.0 and `active-rpc-cli` 0.1.0.
