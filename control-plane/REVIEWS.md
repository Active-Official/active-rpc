# Control plane review record

Independent reviews ran through the GitHub Copilot CLI routed at the Meta Muse
proxy (`muse-spark-1.3-contributor`, reasoning `xhigh`). Each finding was
checked against the source before a fix; the reviewer then re-read the patched
tree.

## Round 1 - live-upgrade implementation

Ten findings, all fixed:

| Severity | Finding | Fix |
|---|---|---|
| medium | `pipeline_depth` used a non-saturating sum | `saturating_add` on both counters |
| medium | cumulative `calls_queued` was captioned as queue depth | renamed to calls accepted/queued with a cumulative caption and a wider scale |
| low | per-run provider registration grew the kernel registry | MCP, HTTP and local-process providers plus their caps are registered once in `PlaneCore::new` |
| low | embedded MCP fallback did not report read-only mode | `set_mode("read-only")` on the embedded core |
| low | unbounded local write queue | `bounded(8)` command queue with immediate 503 |
| low | MCP level accepted out-of-range values | validates before narrowing; `-32602` for bad tool arguments |
| low | UI parsed error JSON as an object | reads response text and reports it |
| low | timeline ticks were mouse-only | `role=button`, `tabindex=0`, Enter/Space handling |
| low | no crate-wide unsafe ban | `#![forbid(unsafe_code)]` |
| low | read-only level POST untested | covered in `tests/api_tests.rs` |

## Round 2 - fixes under review

Two new low findings, both fixed:

- `cp_run_level` narrowed `u64` to `u8` before the range check, so values above
  255 could wrap into a valid level. The check now runs on the `u64`.
- `PlaneCore::run_level` silently clamped out-of-range levels. It now runs
  nothing and the adapters reject the request.

## Round 3 - convergence

**NO NEW FINDINGS.** The reviewer confirmed the u64 guard, the no-clamp rule,
the per-connection HTTP stub with read timeout, panic-safe scenario dispatch,
and the repeated HTTP/process test.

## Gates at convergence

- `cargo test`: 21 engine tests + 4 HTTP tests.
- `cargo clippy --all-targets -- -D warnings`: clean.
- `cargo fmt --check`: clean.
- Browser: zero console/page errors, 20 gauges, 22 ladder passes, 500 JSONL
  lines, 475 timeline ticks, mobile overflow 0.
- Leak scan: no canary and no 32-hex raw capability id in REST, WS, MCP, JSONL,
  status bytes, screenshots or rendered text.
