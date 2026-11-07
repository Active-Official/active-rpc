# Section status (RPC sectional loop)

The loop is `docs/hardening/COPILOT-MARATHON.md` under
`C:\Users\Usuario\Downloads\Active-Absolute-Max-Program\COPILOT-DEEP-AUDIT-LOOP.md`:
hostile read-only review, triage every finding against the real code, failing
test first, minimal fix, targeted tests plus the full gate, re-audit. A section
closes after **two consecutive rounds with no critical, high or medium** finding
(every low fixed or explicitly accepted). Every round is logged in the marathon
with its verdict, dispositions and test names; this table is the index.

Updated 2026-11-06 at `cf5f969`.

| Section | Area | Rounds | State | Evidence |
|---|---|---|---|---|
| R-01 | wire ARP1 | 5 | **closed** | r4 first clean, r5 second clean |
| R-02 | kernel dispatch | 10 | **closed** | r9 first clean, r10 second clean |
| R-03 | capabilities | 6 | **closed** | r5 first clean, r6 second clean |
| R-04 | promises / pipeline | 6 | **closed** | r5 first clean, r6 second clean |
| R-05 | lanes / channels | 5 | clean | r5: no critical/high/medium, two lows fixed; the second consecutive clean round is not on record |
| R-06 | domain operations | 13 | **closed** | r12 first clean, r13 second clean |
| R-07 | domain providers | 47 | clean | r47 CLEAN (six claims held, four lows fixed) |
| R-08 | tools / MCP | 60 | **closed** | r59 and r60 CLEAN |
| R-09 | transports | 23 | **closed** | r22 and r23 CLEAN |
| R-10 | bulk transfer | 17 | open | r16 fixed two mediums (wall-failure accounting, `abort` scope); r17 in flight |
| R-11 | identity | 14 | open | r13 fixed two mediums (child-first rotation, event schema); r14 in flight |
| R-12 | replay | 6 | **closed** | r5 and r6 CLEAN |
| R-13 | receipts | 11 | open | r10's high and two mediums fixed at `68f29ab` (ownership re-checked before every mutation, future timestamps, type-checked readers); its five lows fixed in round 11; r11's audit must come back clean, then r12 |
| R-14 | wasm tools | 5 | **closed** | r3's medium was refuted with a test; r4 and r5 CLEAN |
| R-15 | observability | 5 | **closed** | r2's high and mediums fixed; r4 and r5 CLEAN |
| R-16 | security helpers | 10 | open | r10 found one high (a tainted-blob-only module was secret-free to every domain projection) and the taint-set medium, all fixed with the sticky `held_secret` predicate; r11 and r12 must be clean |
| R-17 | introduction / topics | 6 | open | r6 found one medium (the channel counters charged wire bytes, not the 32-byte inline values) and four lows, all fixed; r7 and r8 must be clean |
| R-18 | CLI | 2 | open | r2 had one high and eight mediums, all fixed; r3 and r4 needed |
| R-19 | control plane | 2 | open | r2 had two highs and six mediums, all fixed; r3 and r4 needed |
| R-20 | fuzz program | 2 | open | r2 had three highs and three mediums, all fixed; r3 and r4 needed |

## What "closed" means here

A section is closed when its marathon entries show two consecutive rounds whose
reviewer verdict is CLEAN (no critical, high or medium). Every low in those
rounds is either fixed in the same round with a named test or accepted with a
reason in the entry. Criticals and highs found in any round are closed only by a
fix with a regression test that fails on the pre-fix code; the entries record
which ones were proved that way.

## Residuals that are not section defects

- **RPC-11** (residuals register): a provider method cannot see the capability
  id, so an object-level destructor (`bulk abort`) is scoped by the object model's
  one-principal rule. Closure is an additive `Call` field.
- **RPC-10**: durable capabilities carry a raw object id with no durable binding.
- Deferred audit items tracked in the program's residuals register: the ARPC-009
  epoch, the Windows job-object tree kill, the export tombstone.

## Reproduce

```bash
bash scripts/local_gate.sh --no-msrv     # fmt, clippy x2, tests x2, doc, benches,
                                         # fuzz, control plane, CLI, hardening, controls
docker run --rm -v "$PWD:/work" -w /work \
  -e CARGO_TARGET_DIR=/tmp/target rust:1.99 bash -c \
  'export PATH=/usr/local/cargo/bin:/usr/bin:/bin; \
   rustup component add rustfmt clippy >/dev/null 2>&1; \
   cargo fmt --all -- --check && cargo test --locked --all-features'
```
