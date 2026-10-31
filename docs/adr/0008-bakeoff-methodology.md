# ADR 0008 — Bakeoff methodology

Status: accepted for AIM-PROP-2026-10 C-2.3.

## Decision

Public RPC bakeoffs compare identical logical work, not marketing narratives.

- **Hardware class:** CPU, physical cores, RAM, OS, kernel, compiler and CPU
  governor are recorded with every run.
- **Workloads:** in-process evaluate, sequential calls and a dependent promise
  chain with the same argument sizes; remote adapters use the same payload and
  connection class.
- **Warmup/iterations:** at least one discarded warmup set; Criterion defaults
  unless a longer measurement window is recorded.
- **Statistics:** p50 and p99 from raw samples, sample count and confidence
  interval. A best-of run is never published.
- **Fairness:** round-trip count and wall time are separate columns. Pipelining
  is compared against the same number of sequential calls; setup is outside the
  measured loop where possible and stated when not.
- **No fabrication:** an unavailable gRPC adapter is a documented gap, not a
  projected win.

## CI gate

The shipped internal matrix (sequential versus pipelined, encode versus
validate) runs in CI with a stored baseline and per-metric tolerance. A
regression beyond tolerance fails unless an ADR and new baseline accompany it.

## Consequences

Results are hardware-bound and reproducible. The performance page names the
class and links the captured run rather than presenting a universal claim.
