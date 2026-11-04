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

The load path is exercised, not just the arithmetic: `tests/cap_delta_load_tests.rs`
runs four concurrent negotiators over TCP for 120 chained deltas each, asserts
that the peer's applied table hashes to the table the sender computed at every
step, that the base table is never mutated in place, and that replaying a spent
delta against the new table is refused with `rpc/capability-table`.

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
| `rpc/topic-not-granted` | a pub/sub topic is outside the capability's topic set |
| `rpc/tool-policy` | the tool policy refuses the call |
| `rpc/revoked` | the capability (or an ancestor) was revoked |
| `rpc/budget-exceeded` | a call, byte or lane budget is exhausted |
| `rpc/unknown-lane` | the lane does not exist or was destroyed |
| `rpc/unknown-channel` | the channel does not exist, or the lane is not subscribed to it |
| `rpc/unknown-promise` | the promise id was never minted here |
| `rpc/promise-cancelled` | the promise was cancelled |
| `rpc/promise-resolved` | the promise was already resolved or rejected |
| `rpc/backpressure` | the local call queue or channel window is full |
| `rpc/identity` | the peer's authenticated identity is missing or does not match the capability's binding |
| `rpc/bulk` | a bulk plan or chunk is malformed, truncated or fails its hash |
| `rpc/replay` | a replay package is malformed, tampered with, or disagrees with the decisions it recorded |
| `rpc/persistence` | a durable capability record is unsealed, already restored, bound to another peer, or names a provider this kernel does not have |
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

### Kernel and domain provider codes

A provider failure is `rpc/provider` with an inner code in the provider's own
namespace. The kernel itself reports two:

| Code | Condition |
|------|-----------|
| `provider/reply-withheld` | a mutating provider ran and applied its effect, but the reply could not be delivered (a post-provider budget or lane refusal); the effect stands and the receipt records the admission, so this is not a retryable budget class |
| `provider/secret-material` | a provider reply would have carried structural secret material and the redaction policy refused it |

The domain provider reports `rpc/domain` with the Active class where the
evaluator failed, and `rpc/budget-exceeded` with the dimension it measured
(`nodes`, `keys`, `value`, `depth`, `wall`, `array_len`).

### MCP adapter codes

An `McpSession` reports adapter failures as `rpc/provider` with one of these
inner codes. Every one is a fail-closed refusal; none is retryable without a new
session:

| Code | Condition |
|------|-----------|
| `mcp/bad-json` | the request line could not be serialised (client bug) |
| `mcp/no-response` | the transport returned nothing for a request |
| `mcp/eof` | the server closed its stdout |
| `mcp/line-too-long` | a line exceeded 1 MiB before parsing |
| `mcp/bad-response` | the response is not a JSON object with `result` or `error`, has neither an `id` nor a `method`, or carries an `error` whose `code` is absent or not an integer |
| `mcp/id-mismatch` | the response `id` is not the integer this client sent, or the frame is a server-initiated request |
| `mcp/desync` | more than `MAX_MCP_NOTIFICATIONS` notification frames arrived for one request, or the session was already poisoned |
| `mcp/bad-number` | a response line holds a numeric literal with no `Value` form: an integer outside `i64`, or a float that is not finite |
| `mcp/initialize`, `mcp/initialize:<code>` | the server answered `initialize` with an error; the numeric code is kept when present |
| `mcp/tool-name` | an advertised tool name is absent or empty, is not `[A-Za-z0-9_.-]{1,128}`, or two tools share a name |
| `mcp/tools` | the handshake result carries no `tools` array |
| `mcp/tool-count` | the server advertised more than `MAX_MCP_TOOLS` (4 096) tools |
| `mcp/spawn:<err>` | the child process could not be started |
| `mcp/cwd` | the working directory could not be pinned |
| `mcp/read:<err>`, `mcp/write:<err>`, `mcp/stdin`, `mcp/stdout` | transport I/O failed |
| `mcp/write:closed` | the server closed its input while a line was being sent |
| `mcp/thread:<err>` | a reader or writer thread could not start |
| `mcp/<code>` | the server returned a JSON-RPC error; `<code>` is its numeric code |

A line past the capability's byte grant is `rpc/budget-exceeded` with dimension
`byte`; the 1 MiB line ceiling still bounds the read. An outgoing request over
1 MiB is `rpc/invalid-argument`, and one past the grant is
`rpc/budget-exceeded`.

A tool name is validated because it becomes an allow-list entry and a method
name. Control characters, bidi overrides and duplicates are refused at
handshake rather than filtered silently, so an operator never sees one name and
grants another.

A frame without an `id` and with a `method` is a **notification**
(`notifications/progress`, `notifications/message`), not an answer. The session
skips a bounded number of them so a spec-compliant server keeps working, then
poisons itself: an unbounded skip would let a server starve the caller with
frames it never asked for. A poisoned session refuses every later call, because
after a desync the next line may belong to a request already abandoned. The
handshake itself is bounded by `DEFAULT_MCP_HANDSHAKE_TIMEOUT_MS` (5 s) unless
the caller passes its own deadline to `handshake_within`.

### HTTP adapter codes (`HttpTool`)

Reported as `rpc/provider` with one of these inner codes:

| Code | Condition |
|------|-----------|
| `http/resolve:<err>` | the base URL did not resolve |
| `http/connect` | no address accepted the connection inside the ceiling |
| `http/status` | the status line is not `HTTP/1.<digit>` with exactly three ASCII digits in `200..=599` |
| `http/interim` | a 1xx interim response arrived; the adapter does not follow it |
| `http/headers` | the header block exceeded 64 KiB or 128 fields, a field name is not an RFC 9110 token, a `content-length` was repeated, non-numeric or not digits, or a whitespace-only line appeared |
| `http/header-not-utf8` | the status line or a header line is not UTF-8 |
| `http/bad-number` | a JSON number has no `Value` form: an integer outside `i64`, or a float that is not finite (a literal with a fraction or an exponent that overflows `f64`) |
| `http/too-complex` | an object or array body has more than 2^20 structural tokens before parsing, or the decoded tree has more than 2^20 nodes |
| `http/body-too-large` | the response body exceeded `min(max_body, 64 MiB)`, by its declared length or by its stream; when the capability's byte grant is the tighter ceiling the refusal is `rpc/budget-exceeded` instead |
| `http/line-too-long` | a status or header line exceeded its own cap; a grant-capped line is `rpc/budget-exceeded` |
| `http/transfer-encoding` | a transfer coding other than `identity` |
| `http/write:<err>`, `http/read:<err>` | socket I/O failed in that direction |
| `http/read:truncated`, `http/read:truncated-body` | the peer closed before a full line or body arrived |
| `http/<status>` | the endpoint answered a status outside 2xx (3xx included: the adapter does not follow redirects) |

The request is `METHOD path HTTP/1.1` with `host`, `connection: close`, and a
`content-length` only for a method defined to carry content (`POST`, `PUT`,
`PATCH`). The request body shares the capability's byte grant: a body past the
grant is `rpc/budget-exceeded` before the connection, and one past the adapter's
`max_request` is `rpc/tool-policy`. A GET sends no body: the request is complete at the empty line, and
extra bytes make simple servers and intermediaries reset the connection instead
of answering. The `max_wall_ms` grant (clamped to 10 s) is **one deadline** for
the exchange from connect onward: connect, write, every header line and the body.
Resolution of the base URL happens before the deadline starts and uses the
system resolver’s own timeout, because the endpoint is the operator’s, not the
peer’s. A server that drips a byte per timeout period cannot stretch the
ceiling. A HEAD,
204 or 304 reply is read as bodyless whatever its headers say. A path is
refused if it contains a byte outside `0x21..=0x7e`, because it is
interpolated into the request line. A leading UTF-8 byte-order mark on an
answer is ignored before the JSON gates and the decode.

### Process adapter codes (`LocalProcess`)

| Code | Condition |
|------|-----------|
| `process/spawn:<err>` | the pinned program could not be started |
| `process/wait:<err>` | waiting for the child failed |
| `process/cwd` | the working directory could not be pinned at construction |
| `process/thread:<err>` | a pipe reader thread could not start; the child is killed |
| `process/signalled` | the child died from a signal, so it has no exit status to report |
| `rpc/budget-exceeded` | the wall or byte grant is zero, the input is past the byte grant, or the output reached the grant-derived ceiling |
| `rpc/timeout` | the call exceeded the effective wall ceiling; the whole process group was killed |
| `rpc/invalid-argument` | a construction path, a working directory, or an argument is not something the adapter can execute |
| `rpc/tool-policy` | an argument is not allowlisted, a prefix-matched argument contains shell syntax, a secret argument was passed, the output exceeded the effective ceiling, or process execution was not granted |

The effective output ceiling is the smaller of `max_output`, 16 MiB and the
capability byte grant, for both streams together. A request body is capped by
`min(max_request, 64 MiB, the grant)`; a response head is capped by
`min(64 KiB, the grant)`, and the head and the body share that grant. A grant
below the shortest possible answer (16 bytes: a status line plus the empty
end-of-head line) is `rpc/budget-exceeded` before the request is sent.

`LocalProcess::new` requires an absolute program path. A bare name would be
resolved from the parent's `PATH`, which is ambient authority: anything that can
write an earlier `PATH` entry would choose the binary a capability runs. The
canonical path is pinned at construction, and the working directory is pinned to
the parent's directory at that moment, so a later `chdir` or symlink swap cannot
redirect the child. A `*` allowlist rule admits a command-line prefix, so an
argument that only a prefix rule admits may not contain shell syntax: with a
shell as the program the rest of the line would be code.

### WASM guest tool codes (`wasm-tools`)

A `wasm_tool::WasmTool` provider reports failures as `rpc/provider` with one of
these inner codes (ADR-0019): `wasm/module`, `wasm/limits`, `wasm/import`,
`wasm/instantiate`, `wasm/memory`, `wasm/entry`, `wasm/fuel`, `wasm/trap`,
`wasm/input`, `wasm/output`. The guest ABI is `memory` plus
`run(len: i32) -> i32` with input at offset 0 and output at offset 65536. ABI v1
allows no imports; ABI v2 lets the embedder grant `env.clock_ms`,
`env.random(ptr, len)` and `env.log(ptr, len)` per tool instance, and refuses
any other import with `wasm/import`.

---

### Channel and topic authority

A channel carries messages in one process; it is not a wire format. The rules a
transport must preserve when it forwards one:

- **Publishing is an explicit grant.** A capability publishes only when its
  attrs carry `publish` (`CapAttrs::allow_publish` or `restrict_topics`), which
  attenuation may drop and never add; without it the answer is
  `rpc/method-not-granted`. `Agent::publish` then requires the capability to
  exist, be unrevoked and be unexpired (`rpc/revoked`), and when it carries a
  topic set the topic must be a member (`rpc/topic-not-granted`). The clock is
  read before the deadline is compared, so a wall-clock kernel cannot publish
  past a lease.
- **Reading is a subscription.** `Agent::recv(lane, channel)` and
  `recv_topic(lane, channel, topic)` require the lane to be in the channel's
  subscriber set; a lane that is not gets `rpc/unknown-channel`, the same answer
  as a missing channel. `Agent::channel(id)` returns counts and names only, never
  a queued payload or a transferred capability id.
- **A topic is bounded text.** 1..=128 bytes, no control characters, and none of
  the characters that reorder or hide rendered text (U+2028/U+2029, bidi
  controls, zero-width and tag characters), checked at the grant, at publish and
  inside `Channel` itself. A channel and provider name follow the same rule.
- **A bound capability needs its peer.** A capability bound with `mint_bound`
  publishes only through `Agent::publish_as`, and the presented peer fingerprint
  must match the binding (`rpc/identity`). A channel cannot prove who published,
  so the unauthenticated `publish` refuses a bound capability outright.
- **Bytes are charged.** The payload's wire size is charged against the
  capability budget intersected with the lane's (`rpc/budget-exceeded`). A
  refused publish charges nothing and queues nothing.
- **A transfer never carries a bound capability.** `Agent::send_as` refuses to
  put a bound capability on a channel; delegation across an identity boundary
  uses `introduce_to` explicitly. Both paths refuse an expired capability.
- **A full channel is backpressure.** The queue ceiling answers
  `rpc/backpressure`; it never drops a message silently.

---

## 6. Transports

| Transport | Framing | Notes |
|-----------|---------|-------|
| in-process | none | envelopes move by value; `bytes_written() == 0` |
| TCP | `u32` length + envelope | cross-process, `MAX_FRAME_BYTES` = 64 MiB |
| shared memory | `u32` length + envelope in a ring | borrowed frame reads via `with_frame` (the decoded envelope owns its payload) |
| QUIC | `u32` length + envelope on one bi-directional stream, one stream per call | TLS with a self-signed certificate on loopback; `start_mutual_tls` verifies a client certificate and exposes the authenticated peer identity |
| HTTP/2 | `POST /active.rpc.v1.Agent/Call`, body is the bare envelope, content type `application/arp1` | feature `http2`; one connection, concurrent streams; a non-200 answer carries an `rpc/...` body |
| Connect/gRPC | HTTP/1.1 `POST /active.rpc.v1.Agent/Call`, body framed as `[0][len u32 BE][envelope]`, content type `application/connect+active-infinity` or `application/grpc+active-infinity` | a malformed frame is a `400` with an `rpc/...` body; HTTP/1.1, one request per connection |

A malformed frame is always an error at the frame boundary: no transport retries,
guesses or forwards a partially decoded envelope.

One stream carries one frame. On QUIC the reader takes the announced length and
then probes for trailing bytes with a `250 ms` window (`STREAM_TAIL_WAIT`): a
byte sent later than that is silently discarded with the stream, never
dispatched. The window is a timing property, not a framing guarantee, so a peer
that must prove "one frame only" should close the stream after the frame.

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

---

---

## 9. Bulk transfer frames

A body larger than one frame travels as a plan plus chunk frames (ADR-0013).
Each frame is the **payload of an ordinary ARP1 call** to a bulk provider:
`plan` opens the transfer, `put` carries one chunk, `missing` asks for the gaps
and `finish` closes it. That is what binds the transfer to authority and to the
byte budget: the kernel charges an envelope payload on ingress, and a capability
that does not grant `put` cannot push a chunk. The layouts below are
little-endian unless stated.

**Plan** (`ARBL`):

```text
"ARBL" | version u8 | chunk_size u32 | total u64 | chunk_count u32 | root [32]
       | chunk_hash [32] * chunk_count
```

`root = Blake3("active-rpc/bulk-root/v1\0", version, chunk_size, total, count,
hashes, len(context), context)`. The context (normally the request id and
capability id of the opening envelope) is **not transmitted**: both sides derive
it, and a decoder recomputes the root and refuses a plan that does not match. A
decoder also refuses a declared `total` above its ceiling and a
`chunk_count` above 65 536 before allocating the hash list.

**Chunk** (`ARBC`):

```text
"ARBC" | version u8 | index u32 | offset u64 | length u32 | hash [32] | bytes
```

`offset` must equal `index * chunk_size`, `length` must match the plan, and
`hash = Blake3("active-rpc/bulk-chunk/v1\0", bytes)`. A duplicate chunk with
identical bytes is idempotent; conflicting bytes are `rpc/bulk`. `length` is at
most 8 MiB; a body decoded under `WireLimits::strict()` caps an envelope payload
at 1 MiB, so the sender selects a chunk size under that profile.

**Resume request** (`ARBM`):

```text
"ARBM" | version u8 | count u32 | index u32 * count
```

Indexes are unique and below `chunk_count`; a request that names more indexes
than the plan has, or one outside it, is `rpc/bulk`.

**Finish** (`ARBF`):

```text
"ARBF" | version u8 | total u64 | root [32]
```

The marker names the transfer the sender believes it completed; a marker whose
root or total differs from the plan is `rpc/bulk`, so a body from another
transfer cannot settle this one.

A receiver assembles only after every index is present and the body verifies
against the plan. The root proves the body matches the plan, not who chose the
plan: a caller that must not accept a substituted plan pins the root it expects
(`with_expected_root`, or the `context` above).

A bulk body is data, never authority: authority stays on the ARP1 envelope that
opens the transfer.

### Receipt log (`ARRL`)

A durable audit log is not an ARP1 message, but it is a format peers and
operators exchange, so its refusal class is part of the contract:
`rpc/receipt`. The layout, chain rules and verification modes are in
ADR-0021 (version 2). `receipts verify` checks the chain without the kernel
secret; `--secret-hex` adds the keyed check over every receipt MAC, and
`--expect-head` pins the chain head a verifier learned out of band, which is the
only way to detect a truncated tail: any record-boundary prefix is a
self-consistent shorter log.

A record carries the decision the kernel took at dispatch
(`admitted` or `refused` plus an `rpc/...` code), because a call that was queued
and then refused is evidence of a refusal. Records carry correlation ids, method
names, times and decisions; they never carry arguments, values, capability ids
or secret material.

### Replay package (`ARRP`)

A recorded session is a second exchanged artifact, refused with `rpc/replay`.
Its layout is in ADR-0018; the parts a consumer must be able to rely on:

```text
magic "ARRP"   version u8   flags u16 (0)   latency_ms u64
op_count u32   ops...       trace_count u32  traces...   checksum blake3[32]
```

An operation is `SetLatency`, `Mint`, `Attenuate`, `Call` or `Revoke`; a call
records the method and the size of the text value replay synthesizes, never
the argument. The kernel's charged wire size is a different number and is in
the `call.queued` trace entry. The trace is
the decision stream plus one `op.*` input entry per operation, so an edit to a
grant, a TTL, a latency or a refused call's method does not match a replayed
trace. The recorder, the encoder and the decoder share one set of limits
(100 000 operations, 1 000 000 trace entries, 64 methods per grant, 1 MiB per
argument and 16 MiB per package, 64 MiB body), so an artifact that is written is
an artifact that reads. The checksum detects corruption, not forgery: a party
that can rewrite the file can recompute it.
