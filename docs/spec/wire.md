# Active RPC wire protocol (`ARP1`, version 1)

**Status:** normative. This document defines the envelope every Active RPC
transport carries, the capability table that travels with it, and the error codes
peers may rely on.

Active RPC is a capability-based, promise-pipelined RPC for Active Infinity
payloads. The envelope is deliberately transport-agnostic: the in-process link,
shared memory, TCP, QUIC and the gRPC/Connect bridge all carry these bytes (the
first two skip serialization but preserve the shape).

```text
0   4  magic "ARP1"
4   1  version (1)
5   1  kind
6   2  flags
8   8  request id
16  .. method, arguments, payload, capability table
```

All integers are little-endian.

---

## 1. Header

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 4 | magic `41 52 50 31` (`ARP1`) |
| 4 | 1 | version (`1`) |
| 5 | 1 | kind |
| 6 | 2 | flags |
| 8 | 8 | request id (echoed by the response) |

### 1.1 Kinds

| Code | Kind | Meaning |
|-----:|------|---------|
| 1 | `Request` | a method call |
| 2 | `Response` | a successful result (first argument is the value) |
| 3 | `Error` | a failure (method field carries the error code) |
| 4 | `Hello` | capability handshake |

### 1.2 Flags

| Bit | Name | Meaning |
|----:|------|---------|
| 0 | `redact` | the caller asks for redacted output |
| 1 | `read_only` | the capability is read-only |
| 2 | `cap_delta` | a negotiated capability-table delta follows the capability slot |

Unknown flag bits are refused (`rpc/wire`).

---

## 2. Body

```text
method      : u32 length | UTF-8 bytes
args        : u32 count | arg*
payload     : u32 length | bytes            (an Active Infinity image, optional)
caps        : u32 count | capability*
delta       : optional, when flag bit 2: base[32] | removed_count u32 | id[16]* | added_count u32 | capability*
```

An envelope with trailing bytes after the capability table is refused.

### 2.1 Arguments

| Tag | Argument | Encoding |
|----:|----------|----------|
| 0 | value | value encoding below |
| 1 | promise | `u64` promise id |
| 2 | capability | 16-byte capability id |

A promise argument makes the call **pipelined**: the kernel keeps the dependent
call at the provider and dispatches it in the batch that resolves the promise.
A capability argument transfers authority explicitly.

### 2.2 Values

| Tag | Value | Encoding |
|----:|-------|----------|
| 0 | `Null` | — |
| 1 | `Bool` | `u8` (`0`/`1`) |
| 2 | `Int` | `i64` |
| 3 | `Float` | IEEE-754 binary64 bits |
| 4 | `Text` | `u32` length + UTF-8 |
| 5 | `List` | `u32` count + value* |
| 6 | `Map` | `u32` count + (`u32` length + key, value)* |
| 7 | `Secret` | — (a marker: there is no encoding for secret bytes) |
| 8 | `Module` | `u32` length + Infinity image bytes |
| 9 | `Path` | `u32` length + UTF-8 dotted path |

`Secret` is the *only* representation of secret material on the wire. There is no
tag that carries secret bytes, so no encoder in this crate can leak one.

Value nesting is capped at 64 levels and every length is checked against the
remaining bytes before allocation (`rpc/wire`). A `Module` value is a **redacted**
projection: secret nodes are replaced by the marker before encoding, because the
wire has no tag that could carry the material.

---

## 3. Capability descriptors

A capability table is `u32 count` followed by descriptors:

| Field | Encoding |
|-------|----------|
| id | 16 bytes |
| methods | `u32` count + (`u32` length + UTF-8)* |
| budget | seven `u64` ceilings: calls, bytes, wall ms, nodes, depth, array length, value size |
| read_only | `u8` |
| redact | `u8` |
| path scope | `u8` present flag + (`u32` length + UTF-8) |

A descriptor whose budget disables a ceiling (any `0`) is refused with
`rpc/capability-table`: there is no unlimited profile on the wire.

### 3.1 Capability-table delta

When flag bit 2 is set, the body ends with:

```text
base        : 32-byte Blake3 of the peer's current canonical table
removed     : u32 count | 16-byte id*
added       : u32 count | capability*
```

A receiver applies the delta only when `cap_table_hash(current) == base`.
Unknown base, unknown removal, duplicate addition or malformed descriptor is
`rpc/capability-table`. A delta never widens authority: added descriptors still
pass the normal attenuation/import checks. Full tables remain the default and
remain valid when the flag is clear.

The table is a *description*, never proof. A receiver must look the id up in its
own registry; an id it did not mint is refused with `rpc/unknown-capability`.

Every budget ceiling must be non-zero: a descriptor that disables a ceiling is
refused. Budgets are charged per call (arguments plus payload) and intersected
with the lane's budget before dispatch.

---

## 4. Envelope limits

`WireLimits` bounds total bytes, arguments, method length, payload, descriptors
and methods per descriptor. Defaults accept real modules (64 MiB envelopes) and
`WireLimits::strict()` is the profile for adversarial surfaces. Exceeding a limit
is `rpc/wire` (or `rpc/capability-table` for the table).

---

## 5. Error codes

Codes are permanent. A peer branches on the code in an `Error` envelope, never on
a message.

| Code | Condition |
|------|-----------|
| `rpc/unknown-capability` | the id is not in the receiver's registry |
| `rpc/method-not-granted` | the capability or provider does not grant the method |
| `rpc/attenuation-escalation` | an attenuation would widen authority |
| `rpc/read-only` | a mutating method on a read-only capability |
| `rpc/path-not-granted` | a path argument is outside the capability's scope |
| `rpc/tool-policy` | the tool policy refuses the call |
| `rpc/revoked` | the capability (or an ancestor) was revoked |
| `rpc/budget-exceeded` | a call, byte or lane budget is exhausted |
| `rpc/unknown-lane` | the lane does not exist or was destroyed |
| `rpc/unknown-channel` | the channel does not exist |
| `rpc/unknown-promise` | the promise id was never minted here |
| `rpc/promise-cancelled` | the promise was cancelled |
| `rpc/promise-resolved` | the promise was already resolved or rejected |
| `rpc/backpressure` | the local call queue or channel window is full |
| `rpc/identity` | the peer's authenticated identity is missing or does not match the capability's binding |
| `rpc/unresolvable-promise` | the promise can never settle |
| `rpc/provider` | the provider failed the call |
| `rpc/domain` | an Active or Infinity domain operation failed (the message carries the Active class, e.g. `X001`) |
| `rpc/payload` | a payload is not a valid Active Infinity image |
| `rpc/wire` | the envelope is malformed or exceeds a limit |
| `rpc/capability-table` | the capability table is malformed or disables a ceiling |
| `rpc/transport` | the transport failed |
| `rpc/transport-unavailable` | the transport is not built or not supported here |
| `rpc/timeout` | a deadline elapsed |
| `rpc/pipelined-cycle` | pipelined calls form a dependency cycle |
| `rpc/invalid-argument` | a caller-supplied argument is out of range |

---

## 6. Transports

| Transport | Framing | Notes |
|-----------|---------|-------|
| in-process | none | envelopes move by value; `bytes_written() == 0` |
| TCP | `u32` length + envelope | cross-process, `MAX_FRAME_BYTES` = 64 MiB |
| shared memory | `u32` length + envelope in a ring | zero-copy reads via `with_frame` |
| QUIC | `u32` length + envelope on one bi-directional stream, one stream per call | TLS with a self-signed certificate on loopback; `start_mutual_tls` verifies a client certificate and exposes the authenticated peer identity |
| Connect/gRPC | HTTP/1.1 `POST /active.rpc.v1.Agent/Call`, body framed as `[0][len u32 BE][envelope]`, content type `application/connect+active-infinity` or `application/grpc+active-infinity` | a malformed frame is a `400` with an `rpc/…` body; the same framing fits an HTTP/2 gRPC server |

A malformed frame is always an error at the frame boundary: no transport retries,
guesses or forwards a partially decoded envelope.

---

## 7. Versioning

- The version byte changes only for an incompatible layout change.
- Kind, flag, argument, value and error codes are permanent.
- New value or argument tags may be added in a later version; a reader refuses a
  tag it does not know rather than skipping it, because a skipped argument would
  change the call's meaning.

---

## 8. What a decoded envelope guarantees

1. Every length and count fit inside the buffer; nothing allocates on a claim.
2. The body ends exactly at the end of the capability table.
3. Every capability descriptor has a valid budget and a non-empty id.
4. No argument carries secret bytes: `Secret` is a marker, and module payloads
   are redacted projections.
5. The envelope can be re-encoded to the same bytes.
6. Value nesting stays within 64 levels.
