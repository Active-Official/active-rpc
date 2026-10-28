# What is safe to log

This is the operator-facing rule for both crates. It implements H5.5 and H7.2.

## Allowed

- module size, node/edge/string/blob counts, section spans;
- the content hash (32 bytes, hex) and the dialect hash;
- node kinds and ids, table field names **after redaction**;
- capability correlation ids (`CapId::correlation_id`), lane ids, promise ids,
  job ids;
- error codes (`infinity/*`, `rpc/*`) and the reason category;
- budget dimensions and the name of the ceiling that fired;
- provider names and method names that are not secret.

## Forbidden

- secret bytes or secret text, in any encoding (hex, base64, lossy UTF-8);
- a string that contains a secret literal, even if the string itself is not a
  `Secret`;
- the raw 16-byte capability id (`CapId::hex`) — possession is authority;
- a module payload, a tool argument, or a tool response body;
- a derived value that reveals secret length or content.

## The redaction marker

`***SECRET***` is the only public secret constant. It is stable, contains no
secret material, and is a fixpoint: a string that already contains the marker is
not redacted again into a different shape.

## Examples

```text
ok:   module hash=8f3c… nodes=12 edges=11 secrets=1
ok:   cap correlation=4a1f… lane=main method=stats
ok:   call refused code=rpc/revoked job=7
bad:  module Debug=InfinityModule { bindings: [("token hunter2", …)] }
bad:  cap=0123456789abcdef0123456789abcdef
bad:  provider error: expected "hunter2"
```

## How the guarantee is enforced

- `SecretBytes` has no `Display`, `Debug`, `Serialize`, equality or ordering
  path that reveals it.
- `Debug for InfinityModule` and `Debug for CapId` are redacting formatters.
- The JSON and Protobuf projections are tested against a canary in every
  metadata position.
- The red-team battery scans `Debug`, events, errors and projections for the
  canary and for raw capability bits.
- `tests/api_surface.rs` and `scripts/api_surface.py` keep a public
  secret-accessor from being added.

## What is not protected

- A fully compromised host, a debugger attached to the process, or a core dump
  taken with secret memory still resident.
- A caller that deliberately serializes a secret with `hex()` or writes it to a
  file outside the library.
- Secret length (the length is used by budgets and is not hidden).
