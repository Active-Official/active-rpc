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

## Round 3 - convergence at the pre-chrome tree

**NO NEW FINDINGS.** The reviewer confirmed the u64 guard, the no-clamp rule,
the per-connection HTTP stub with read timeout, panic-safe scenario dispatch,
and the repeated HTTP/process test. At that point the suite had 22 engine tests
plus 4 HTTP tests.

## Round 4 - shipped-tree review (D2-D6, launch harness, refusal KPI)

Five low findings, all fixed:

| Severity | Finding | Fix |
|---|---|---|
| low | `launch_check.py` fallback used `cargo build` without `--locked` | builds with `--locked` |
| low | launch proof covered only the happy path | now runs `tool-policy`, asserts `calls_refused` +1, `tool_refusals` +1, and both event facets |
| low | identical repeated refusals collapsed into one event | kernel events are captured by a `kernel_events_seen` cursor; every new event is recorded once with no content dedupe |
| low | MCP captures were listed but not referenced | both READMEs now show the MCP light/dark picture |
| low | `dash-hero.svg` was used but absent from the RPC manifest | D1 listed alongside D2-D6 |

## Round 5 - convergence

**NO NEW FINDINGS.** The reviewer re-read the patched tree and confirmed the
locked build, the negative-path launch assertion, the cursor capture with no
content dedupe, the MCP picture and the D1 manifest row.

## Round 6 - kernel event-tape wrap

**NO NEW FINDINGS.** `Kernel` now tracks `events_total`, `Agent::total_events()`
exposes the monotonic count, and `PlaneCore` captures
`start = tape.len() - min(total - seen, tape.len())`. The reviewer confirmed the
counter increments on every append including evictions, the cursor advances only
after capture, and the new test drives the shipped `PlaneCore` past 16,384
kernel events before proving a post-wrap scenario still contributes real kernel
events. `cargo test` (control-plane) reports 25 engine tests.

## Gates at convergence

- `cargo test`: 25 engine tests + 4 HTTP tests.
- `cargo clippy --all-targets -- -D warnings`: clean.
- `cargo fmt --check`: clean.
- Committed two-launch harness: both launches reproduce 12 queued calls and 7
  provider round-trips, plus the tool-policy refusal deltas.
- Browser: zero console/page errors, 20 gauges, 22 ladder passes, 500 JSONL
  lines, 494 timeline ticks after the ladder, mobile overflow 0, and
  MCP `cp_metrics` matching the rendered queue-depth and promise-record gauges.
- Leak scan: no canary and no 32-hex raw capability id in REST, WS, MCP, JSONL,
  status bytes, screenshots or rendered text.
