# Bakeoff adapters

The `bakeoff` benchmark compiles today and measures the shipped Active path.
Competitor adapters are intentionally gated behind C-7.3 so no unmeasured
number can appear in the performance page:

- Infinity: `serde_json`, `prost`, `flatbuffers`, `rkyv`
- RPC: gRPC/Connect sequential and pipelined equivalents

Methodology: `docs/adr/` bakeoff ADR.
