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
| 1 | promise | `u64` promise id. An *envelope* never carries this kind: the decoder accepts it, and every envelope entry point refuses it as `rpc/wire` before any ownership check. The ownership rule above applies to argument lists the embedder built and queues for a peer, which is `call_as(Some(peer.identity()), ...)`; `call_peer` is a transport entry point and runs the authority-argument guard, so a promise argument never reaches it. |
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

`WireLimits` bounds total bytes, arguments, method length, payload, descriptors,
methods per descriptor, the cumulative value count and the width of one value.
Defaults accept real modules (64 MiB envelopes) and `WireLimits::strict()` is the
profile for adversarial surfaces. Exceeding a limit is `rpc/wire` (or
`rpc/capability-table` for the table).

The default method ceiling is 1024 bytes, the same number
`kernel::MAX_GRANTED_METHOD_BYTES` and `receipts::MAX_METHOD_BYTES` use: a name a
capability may grant is a name every transport in this crate can encode.
`strict()` tightens it to 64 for adversarial surfaces.

`Envelope::encode` validates against the same limits the decoder applies —
including the value count, the width of one list or map, a zero capability id, a
descriptor that grants no method, a disabled budget ceiling and a duplicate id
across the table and its delta — so an encoder cannot emit a frame this crate's
own reader refuses.

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
| `rpc/revoked` | the capability (or an ancestor) was revoked or its lease ended in the clock domain that minted it; a lease from the other clock domain is `rpc/identity` |
| `rpc/budget-exceeded` | a call, byte or lane budget is exhausted |
| `rpc/unknown-lane` | the lane does not exist or was destroyed |
| `rpc/unknown-channel` | the channel does not exist, or the lane is not subscribed to it |
| `rpc/unknown-promise` | the promise id was never minted here |
| `rpc/promise-cancelled` | the promise was cancelled |
| `rpc/promise-resolved` | the promise was already resolved or rejected |
| `rpc/backpressure` | the local call queue or channel window is full |
| `rpc/identity` | the peer's authenticated identity is missing, does not match the capability's binding, or cannot be a binding at all (a zero or loopback digest); a capability's deadline belongs to the other clock domain; an out-of-band answer comes from a peer that did not queue the promise, or from one whose certificate has since rotated away; an *in-process* pipelined argument names a promise another principal queued; also an *in-process* misuse of a borrowed imported handle (it cannot introduce, rebind, attenuate or revoke the owner's authority; exporting one is `rpc/persistence`) |
| `rpc/bulk` | a bulk plan or chunk is malformed, truncated or fails its hash; also a provider state refusal — no transfer is active, a different transfer is already active, a body is incomplete, a completed body has not been taken, or a `finish` is frozen because three under-resourced attempts are spent. A state refusal is recoverable by planning again for the slot, by granting the body's wall (`assembly_wall_ms`) or by `abort` for a frozen finish; a re-plan does not clear the freeze itself, and the chunks survive either way. A hash or framing fault is not |
| `rpc/replay` | a replay package is malformed, tampered with, or disagrees with the decisions it recorded |
| `rpc/persistence` | a durable capability record is unsealed, already restored, or names a provider this kernel does not have; a record restored by a different peer is `rpc/identity` |
| `rpc/unresolvable-promise` | the promise can never settle |
| `rpc/provider` | the provider failed the call |
| `rpc/domain` | an Active or Infinity domain operation failed; the Active class (e.g. `X001`) is carried in the local `Display` only, not on the wire or in the trace |
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
namespace. The kernel itself reports `rpc/provider` (a provider panicked or
vanished), `wasm/trap` (a panic inside the kernel's own egress policy) and
`provider/reply-withheld`; the domain provider reports `provider/redaction`
and `provider/object`; `provider/egress-panic` is the kernel's own code for a
panic inside the egress policy walk, which any provider can trigger. An error envelope carries the inner code when it is
ASCII and at most 64 bytes (`Envelope::error`), and falls back to `rpc/provider`
otherwise, so the destination field stays decodable under the strict profile.

| Code | Condition |
|------|-----------|
| `provider/reply-withheld` | a provider may have applied its effect, but the reply could not be delivered or accepted: a post-provider budget or lane refusal, a post-send adapter refusal on a call that could have changed something, or a process child that outlived its ceiling; the effect stands and the receipt records the admission, so this is not a retryable budget class |
| `provider/secret-material` | a provider reply would have carried structural secret material and the redaction policy refused it |
| `provider/redaction` | the provider could not build its redacted projection (an encode fault in its own reply) |
| `provider/object` | the capability names an object the provider no longer holds |
| `provider/egress-panic` | the egress policy walk (redaction or the structural-secret check) unwound while inspecting this provider's reply; the reply is refused and the provider's own code never saw it. It is not attributed to any adapter, so a `wasm/trap` in a receipt is always the guest's |

The domain provider reports `rpc/domain` where the evaluator failed (the Active
class stays local) and `rpc/budget-exceeded` with the dimension it measured
(`nodes`, `keys`, `value`, `depth`, `wall`, `array_len`).

### MCP adapter codes

An `McpSession` reports adapter failures as `rpc/provider` with one of these
inner codes. `initialize` must answer `protocolVersion` `2025-06-18`; anything
else is `mcp/bad-response` before the lifecycle notification is sent. Every one is a fail-closed refusal. None needs a new session except
the ones that poison it (every answer-side fault, including a receive deadline
(`rpc/timeout` on the answer), `mcp/line-too-long`, `mcp/too-complex`,
`mcp/desync`, `mcp/id-mismatch`, `mcp/bad-response`, `mcp/bad-number`, `mcp/eof`,
`mcp/no-response` and `mcp/read:<err>`; a write that fails after hand-over:
`mcp/write:<err>` other than `mcp/write:closed`, which poisons without claiming
an effect; and the reader-slot refusal `mcp/thread:too many readers`); a
JSON-RPC `error` from the server leaves the session usable, which is the
asymmetry recorded below. The byte grant is checked first when it is the tighter
bound: a line
past the grant is `rpc/budget-exceeded` (or a withheld reply on a writable call).
A line past only the static 1 MiB ceiling is `rpc/invalid-argument` (a request) or
`mcp/line-too-long` (an answer). Every answer-side refusal poisons the
session, including the grant one: before parsing, the client cannot tell an
over-grant notification (whose answer is still queued) from the answer itself.

Every adapter applies one refusal order - budget, payload, secret, scope,
argument bytes, method - so the same malformed call reports the same first
code whichever adapter it reached; a per-adapter order would fingerprint the
handle and probe its policy.

| Code | Condition |
|------|-----------|
| `mcp/bad-json` | the in-memory test transport could not parse a request line; the real transports report a serialisation failure as `rpc/invalid-argument` before anything is written |
| `mcp/no-response` | the in-memory test transport had no answer queued; a real transport reports `mcp/eof` or `mcp/read:<err>` instead |
| `mcp/eof` | the server closed its stdout |
| `mcp/queue` | the writer queue stayed full until the ceiling; the frame never reached the writer, so the session stays usable |
| `mcp/not-sent` | the deadline had passed before anything was written; the frame never reached the wire, so the session stays usable |
| `mcp/line-too-long` | a line exceeded the static 1 MiB ceiling before parsing, whatever the grant; the session is poisoned |
| `mcp/bad-response` | the response is not a JSON object with `result` or `error`, has neither an `id` nor a `method`, or carries an `error` whose `code` is absent or not an integer; the session is poisoned in every case |
| `mcp/too-complex` | the answer text holds more structural tokens than `MAX_JSON_NODES`, the tree does, the answer text nests past the wire depth before parsing, or the tree is past it; the session is poisoned, and a writable call reports it as a withheld reply |
| `mcp/id-mismatch` | the response `id` is not the integer this client sent, or the frame is a server-initiated request |
| `mcp/desync` | more than `MAX_MCP_NOTIFICATIONS` notification frames arrived for one request, or the session was already poisoned |
| `mcp/bad-number` | a response line holds a numeric literal with no `Value` form: an integer outside `i64`, or a float that is not finite |
| `mcp/initialize`, `mcp/initialize:<code>` | the server answered `initialize` with an error; the numeric code is kept when present |
| `mcp/tool-name` | an advertised tool name is absent or empty, is not `[A-Za-z0-9_.-]{1,128}`, is made only of dots (`.`, `..`), or two tools share a name |
| `mcp/tools` | the handshake result carries no `tools` array |
| `mcp/tool-count` | the server advertised more than `MAX_MCP_TOOLS` (4 096) tools |
| `mcp/spawn:<err>` | the child process could not be started |
| `mcp/cwd` | the working directory could not be pinned |
| `mcp/read:<err>`, `mcp/write:<err>`, `mcp/stdin`, `mcp/stdout` | transport I/O failed |
| `mcp/write:closed` | the writer thread never took the frame (its queue was closed): the session is poisoned and the call is not reported as a withheld reply, because nothing left |
| `mcp/write:lost` | the frame was handed to the writer, which then died before acknowledging it: the session is poisoned and a writable call is a withheld reply |
| `mcp/thread:<err>` | a reader or writer thread could not start, or the process-wide reader-slot ceiling is spent (`too many readers`) |
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
| `http/headers` | the header block exceeded 64 KiB or 128 fields, a field name is not an RFC 9110 token, a `content-length` was repeated, non-numeric or not digits, or a whitespace-only line appeared; a header flood past the capability's byte grant is `rpc/budget-exceeded` instead |
| `http/header-not-utf8` | the status line or a header line is not UTF-8 |
| `http/bad-number` | a JSON number has no `Value` form: an integer outside `i64`, or a float that is not finite (a literal with a fraction or an exponent that overflows `f64`) |
| `http/too-complex` | an object or array body has more than 2^20 structural tokens before parsing, the decoded tree has more than 2^20 nodes, the answer text nests past the wire depth before parsing, or the tree is past it |
| `http/body-too-large` | the response body exceeded `min(max_body, 64 MiB)`, by its declared length or by its stream; when the capability's byte grant is the tighter ceiling the refusal is `rpc/budget-exceeded` instead, except a declared length past the static 64 MiB ceiling, which is always this code because no grant can admit it |
| `http/line-too-long` | a status or header line exceeded its own cap; a grant-capped line is `rpc/budget-exceeded` |
| `http/transfer-encoding` | a transfer coding other than `identity` |
| `http/write:<err>`, `http/read:<err>` | socket I/O failed in that direction |
| `http/read:truncated`, `http/read:truncated-body` | the peer closed before a full line or body arrived |
| `http/<status>` | the endpoint answered a status outside 2xx (3xx included: the adapter does not follow redirects) |
| `rpc/tool-policy` | the base is not `http://host:port` with a printable scheme and authority (a scheme other than `http`, a path, query or fragment, a control character, userinfo, no authority, no port, a port outside `1..=65535`, or a host that is not a DNS name or an IP literal); a path or allowlist entry is ambiguous (dot segment, `;` matrix parameter, percent escape, query, fragment, backslash, double slash or non-printable byte); the request body is past `max_request`; or the call carries a secret or a path scope the adapter cannot enforce |

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
204 or 304 reply is read as bodyless whatever its headers say. A base must be `http://host:port` and nothing else: a path,
query or fragment would either be dropped (retargeting the request at another
resource on the same authority) or concatenated with every request path, a
control character would forge a request head or a log line, and any other shape
is an endpoint this adapter cannot reach. That includes a scheme other than
`http` (matched case-insensitively and stored lowercase: the adapter speaks
plain HTTP, with no TLS), userinfo, a missing port, a port outside `1..=65535`,
an empty authority, an `http://host/` trailing slash and any byte outside
`0x21..=0x7e`. The reason is the same in every case: `perform` resolves the
authority with `ToSocketAddrs`, which needs `host:port`, so a shape it cannot
use would otherwise arrive as the retryable `http/resolve` class instead of a
configuration fault. `HttpTool::try_new` refuses such a
base at construction. `HttpTool::new` refuses every call with
`rpc/tool-policy`; it drops an authority that is itself unusable, and keeps a
usable authority (for the operator's log) when only the tail was wrong, so the
fault is never reported as a retryable `http/resolve`. A path is
refused if it contains a byte outside `0x21..=0x7e`, a dot segment, a `;` matrix
parameter (container peers strip `;name=value` before resolving), a percent
escape, a backslash, a double slash, a query or a fragment: the allow-list is an
exact string and the peer normalizes, so an ambiguous entry could name a
different resource. `HttpTool::try_new` refuses such an entry at construction and
`HttpTool::new` drops it. A body that carries a module or a non-finite number,
or one nested past the wire depth, is `rpc/invalid-argument`: the
`rpc/tool-policy` row above covers policy refusals only. A capability with a path scope is refused
(`rpc/tool-policy`): the kernel compares dotted paths, which cannot confine a
URL path, so the scope would look like confinement while only the allow-list
confined the call. The request head is charged against the byte grant beyond a
256-byte framing allowance, so a megabyte of `base` or an allowlisted long path
cannot be written under a tiny grant. A non-2xx answer is returned as
`http/<status>` without reading its body, so a hostile endpoint cannot force up
to the grant of buffering per refusal. A leading UTF-8 byte-order mark on an
answer is ignored before the JSON gates and the decode.

### Process adapter codes (`LocalProcess`)

| Code | Condition |
|------|-----------|
| `process/spawn:<err>` | the pinned program could not be started |
| `process/wait:<err>` | waiting for the child failed after it was spawned; reported as a withheld reply |
| `process/cwd` | the working directory could not be pinned at construction |
| `process/thread:<err>` | a pipe reader thread could not start; the child is killed and the refusal is a withheld reply |
| `process/signalled` | the child died from a signal, so it has no exit status; a withheld reply |
| `rpc/budget-exceeded` | the wall or byte grant is zero, or the input is past the byte grant (both before the spawn) |
| `rpc/invalid-argument` | a construction path, a working directory, or an argument is not something the adapter can execute |
| `rpc/tool-policy` | an argument is not allowlisted, a prefix-matched argument contains shell syntax, a secret argument was passed, or process execution was not granted |
| `provider/reply-withheld` | every post-spawn refusal: the wall deadline (the whole process group is killed), an output stream past the effective ceiling, a reader thread failure, a wait fault, or a signalled child |

The effective output ceiling is the smaller of `max_output`, 16 MiB and the
capability byte grant, for both streams together. The argument line is charged
against the same grant, so a direct caller cannot pass a megabyte of argv under
a one-byte grant. Every refusal decided after the spawn is
`provider/reply-withheld`: the child ran, the effect may stand, and an
idempotent retry must not fork it again. The pre-spawn refusals (a zero grant,
the input past the grant, the allowlist, a secret argument, the missing process
grant) keep their own class.

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
`wasm/input`, `wasm/output`, `wasm/output-limit`. The guest ABI is `memory` plus
`run(len: i32) -> i32` with input at offset 0 and output at offset 65536. ABI v1
allows no imports; ABI v2 lets the embedder grant `env.clock_ms`,
`env.random(ptr, len)` and `env.log(ptr, len)` per tool instance, and refuses
any other import with `wasm/import`.

The capability's byte grant is one budget for the whole call: the input copy,
the returned output, the guest log the host buffers and the entropy drawn by
`env.random` are summed against it, and a refusal is `rpc/budget-exceeded` with
dimension `byte`. The static `max_output_bytes` and `max_log_bytes` still apply;
the tighter ceiling decides the code, so `wasm/output-limit` maps to
`rpc/budget-exceeded` only when the grant share is the tighter bound, and a
guest's own `-1` stays `wasm/output`.

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
| TCP | `u32` length + envelope | cross-process, `MAX_FRAME_BYTES` = 64 MiB; a post-handler refusal is `provider/reply-withheld` |
| shared memory | `u32` length + envelope in a ring | borrowed frame reads via `with_frame` (the decoded envelope owns its payload) |
| QUIC | `u32` length + envelope on one bi-directional stream, one stream per call | TLS with a self-signed certificate on loopback; `start_mutual_tls` verifies a client certificate and exposes the authenticated peer identity; a post-handler refusal, including one past the reply budget, is `provider/reply-withheld` |
| HTTP/2 | `POST /active.rpc.v1.Agent/Call`, body is the bare envelope, content type `application/arp1` | feature `http2`; one connection, concurrent streams; a non-200 answer carries an `rpc/...` body, or `provider/reply-withheld` once the handler has run |
| Connect/gRPC | HTTP/1.1 `POST /active.rpc.v1.Agent/Call`, body framed as `[0][len u32 BE][envelope]`, content type `application/connect+active-infinity` or `application/grpc+active-infinity` | a malformed frame is a `400` with an `rpc/...` body and a post-handler refusal carries `provider/reply-withheld`; HTTP/1.1, one request per connection |

A malformed frame is always an error at the frame boundary: no transport retries,
guesses or forwards a partially decoded envelope. A body that stops short of its
declared `content-length` is `rpc/wire`, never a retryable `rpc/transport`: a
caller that retried a mutating call would execute it twice. A frame that reaches
the decoder intact but fails to decode also ends the session on TCP; a caller
that ignores the error must not read the next frame as if the peer were healthy.

Both ends of a transport enforce the same profile: a sender encodes with its own
`WireLimits` (`encode_with_limits`), so a strict transport refuses to emit a
frame its own decoder would reject instead of poisoning the link.

An answer must belong to its call. A response echoes the request id; an error
echoes it or carries id `0`, which is the id a peer writes when the frame was
refused before its id could be read. `TcpTransport::call`, `QuicClient::call`,
`Http2Client::call` and `ConnectClient::call` all enforce it through
`Envelope::answers`; anything else (another call's answer, a response with id
`0`, a request) is `rpc/wire`. A shared-memory segment is one ring with no
request/response pairing, so it offers `send`/`recv` only.

A served TCP connection has a total lifetime (`DEFAULT_CONNECTION_LIFETIME`, ten
minutes) as well as a per-frame deadline: a peer that sends a valid frame just
inside every per-frame deadline must not hold a serial server forever. A refusal
that ends a connection drains for up to 150 ms before the socket closes (so a
reset cannot discard the error envelope); a serial server therefore spends at
most that long on a refused peer.
`serve_connection_within` takes an explicit deadline. The frame deadline
(`with_timeout`, default 30 s) bounds the whole **write** of one frame as well as
one read, re-armed before each call: a maximum-size frame therefore needs the
link to carry it inside the deadline, and a slow link must raise it with
`with_timeout` rather than assume the ceiling alone governs.

A refusal decided after the request reached the peer is a **withheld reply** for
a call that could have changed something: the tool may have run, so the caller
gets `provider/reply-withheld` (the receipt records the admission and an
idempotent retry returns the same outcome instead of executing again). The
judgement is the capability's method: a get over HTTP keeps its own code (a
404 is a status, not a withheld write), while `post` and `request` withhold
whatever method text they carry — the same axis the kernel sees — and a
process adapter, whose child always ran, withholds every post-spawn refusal. A pre-send failure (a resolve, a connect, a request-line
budget check) always keeps its class, so a deployment that cannot reach the
peer never burns an idempotency key. This applies to the MCP answer path (an
over-grant line, a malformed or mismatched answer), to the HTTP adapter (a
non-2xx status for a mutating method, an unparseable 2xx answer, a body past
the grant or the static ceiling) and to the process adapter (a deadline, an
output overrun, a wait fault). The MCP session is poisoned in either case,
because before parsing the client cannot tell an over-grant notification (whose
answer is still queued) from the answer itself.

Two deliberate asymmetries. A JSON-RPC `error` object from an MCP server keeps
its `mcp/<code>` on a writable call: MCP has its own tool-level outcome
(`result.isError`), which the adapter passes through as content rather than
reinterpreting, so an `error` object is read as the tool declining. The class
is documented, not enforced by the adapter; a retry after such an `error`
re-executes a mutating tool, an accepted residual because the peer chooses a
non-committal class. And the kernel's mutating axis for the HTTP adapter is
the capability's method: `get` keeps its own code, `post` and `request` withhold
whatever method text they carry, which is over-conservative for a
`request`-with-`GET` and never a claim that a read had an effect.

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
`plan` opens the transfer, `put` carries one chunk, `missing` asks for the gaps,
`finish` closes it and `abort` discards it. That is what binds the transfer to
authority and to the byte budget: the kernel charges an envelope payload on
ingress, and a capability that does not grant `put` cannot push a chunk. The
layouts below are little-endian unless stated.

**Plan** (`ARBL`):

```text
"ARBL" | version u8 | chunk_size u32 | total u64 | chunk_count u32 | root [32]
       | chunk_hash [32] * chunk_count
```

`root = Blake3("active-rpc/bulk-root/v1\0", version, chunk_size, total, count,
hashes, len(context), context)`. The context (normally the request id and
capability id of the opening envelope) is **not transmitted**: both sides derive
it, and a decoder recomputes the root and refuses a plan that does not match. A
decoder also refuses a declared `total` above its ceiling (1 GiB by protocol) and
a `chunk_count` above 32 700 before allocating the hash list. The count is chosen
so the plan **envelope** fits `WireLimits::strict()`, which caps the whole frame
at 1 MiB: the 53-byte header plus 32 bytes per chunk must leave room for the
envelope framing, a capability descriptor with a `max_path` scope and a one-entry
cap delta (about 1.6 kB together). A full 1 GiB body therefore needs a chunk of
at least 32 837 bytes (`ceil(2^30 / 32 836)` is 32 701, one over the
ceiling), and a test encodes and decodes
the maximal plan under the strict profile with such a descriptor and a delta.

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

Indexes are below `chunk_count`; a duplicate is removed, so the decoded list can be
shorter than the frame's count. A request that names more indexes
than the plan has, or one outside it, is `rpc/bulk`.

**Finish** (`ARBF`):

```text
"ARBF" | version u8 | total u64 | root [32]
```

The marker names the transfer the sender believes it completed; a marker whose
root or total differs from the plan is `rpc/bulk`, so a body from another
transfer cannot settle this one.

A receiver assembles only after every index is present and the body verifies
against the plan. A `finish` that cannot succeed leaves the stored chunks in
place: a refusal never destroys bytes the caller already paid to transfer. The
root proves the body matches the plan, not who chose the plan: a caller that must
not accept a substituted plan pins the root it expects (`with_expected_root`, or
the `context` above). `BulkProvider::with_context` supplies that context on the
provider side, because `Provider::invoke` carries no request id or capability id;
without a context or a pinned root a transfer is checked against corruption only.
A provider has one context, so an exchange that needs its own context (request
id plus capability id) uses its own provider instance.

**Provider state and replies.** The provider keys both its in-progress transfer
and its completed body by the capability's **object**, which is what
`Provider::invoke` carries. Attenuation preserves the object, so two capabilities
derived from the same grant share one slot: an object is expected to have one
principal, and a delegated capability observes and settles its parent's
transfer. `Provider::on_drop` releases the object's transfer and any untaken
body. An incomplete transfer is released after 60 s of inactivity and never later
than 1 hour after it opened, a finished, untaken body after 10 minutes, and its
digest reply with it, all measured against the kernel-stamped `Call::now_ms`. `plan`
refuses to open a new transfer for an object whose completed body has not been
taken (`rpc/bulk`), so a body is never silently dropped inside its window.
`abort` drops whatever the object holds — an open transfer, an untaken body
and its digest reply — and answers one constant shape, `aborted: true`, so a
capability that grants only `abort` learns nothing about whether another
principal held state on the object. It
is the caller's own way out of a transfer it no longer wants or cannot finish:
a refusal must never destroy a paid body, so the party that owns the object must
be able to say so. It acts on the **object**, like every other bulk method, so
it inherits the object model's rule that an object has one principal: a host
that mints a second capability on the same object gives that party the right to
discard the object's state. It is idempotent and needs no plan.
`missing` answers the indexes the request frame names (page-capped at 1 024, with
`more` and `remaining`; an empty payload asks for the lowest window), refreshes
the idle window, and never expires a transfer by idleness: a read-only
capability can poll but cannot destroy another capability's chunks. The absolute
lifetime below still applies to a poll, so polling cannot hold a transfer
forever. `finish` is idempotent per object until a new plan is accepted for it: a
repeated marker returns the same reply, even after the host takes the body,
because the effect already landed. The reply is `length`, `canonical` (whether
the body has a content address), `body_hash` (the raw Blake3 digest
of the body: a transfer-integrity value, **never** a content address; omitted for
a redacting call) and, when the body is an Active Infinity image, `content`: the
canonical content address of the **redacted** image, the same value the domain
provider serves. When the address could have been computed but was not,
`canonical` is false and `content_error` says why (`wall`: the grant was spent
before classification, so the reply does not say whether the body is an image;
`parser`: an image that cannot be redacted). The reply is recorded and replayed, so a degraded reply says so
rather than looking like a body that is not an image. A grant must cover `BulkPlan::required_grant()` bytes (plan
frame, chunk frames, finish marker and a per-call reply allowance) and
`BulkPlan::required_calls()` calls (one pass plus a gaps-only resume's `missing`
pages): `total + 53 × chunk_count` pays for the chunk frames only. A caller that
may reconnect and re-send every frame instead reserves
`BulkPlan::required_grant_with_resume()` bytes and
`BulkPlan::required_calls_with_resume()` calls, which is roughly two passes.
Four more dimensions bound the same transfer. The wall grant should cover
`BulkPlan::required_wall_ms()` (assembly, verification, digest and the redacted
content address, linear in the body) **on both the capability and the lane**,
because the kernel meters a call against the narrower of the two
(`required_lane_wall_ms()` is the same number). That is the recommended sizing;
`BulkPlan::assembly_wall_ms()` is the estimate the freeze is judged against — the
body's own cost at the documented rate, a per-chunk term and 100 ms of slack —
so a deployment that mints narrow grants can still finish a small body. The lane's cumulative
`max_bytes` must cover `BulkPlan::required_lane_bytes()`. A provider built with
`with_max_live_bytes` refuses with `rpc/budget-exceeded` a plan that would push
the bytes it holds past that bound, where each open transfer reserves twice its
announced total (the stored chunks and the assembly buffer) plus the plan's own
hash vector (32 bytes per chunk and the 53-byte header), because the plan is
retained for the whole transfer; a `finish` of an image adds a third, transient
body copy for the redaction. A `finish` that runs out of wall is counted: **every**
such failure increments the transfer's count, whatever the grant, because an
attempt that presents the body's own wall and still expires is evidence that the
estimate is wrong for this host. After three failures at a grant the transfer
refuses with `rpc/bulk` before any work, so three cheap frames cannot buy
repeated copies, and repeating the same refused grant does not get a fresh
allowance. The only thing that clears the count is a grant **strictly wider**
than one that has already failed — a price the transfer has not refused — which
is why the sizing to mint is `required_wall_ms()`. The stored chunks are
**never** destroyed by a refusal (a body the caller paid to transfer survives
every refusal), and a refusal that did no work (the deadline was already spent
when the assembly was due to start) does not count. A frozen transfer has two
ways out: the host mints a wider grant, or the caller abandons it with `abort`.
A same-root `plan` frame does **not** clear the freeze, which is what stops a
53-byte frame from re-assembling a paid body. The verification pass is inside
the wall grant, chunk by chunk; the redaction pass of a valid image runs once it
starts, and a reply degraded because the grant was spent (`content_error: wall`)
is recomputed **once** on a later `finish` that still has wall left.

A bulk body is data, never authority: authority stays on the ARP1 envelope that
opens the transfer.

### Receipt log (`ARRL`)

A durable audit log is not an ARP1 message, but it is a format peers and
operators exchange, so its refusal class is part of the contract:
`rpc/receipt`. The layout, chain rules and verification modes are in
ADR-0021 (version 2). `receipts verify` checks the chain without the kernel
secret. Two additions change what the answer means: `--receipt-key-file` gives
the verifier the derived receipt key
(`Agent::receipt_key`, `derive_receipt_key`) and checks every receipt MAC — the
key is symmetric, so a verifier that holds it can also forge, and it must never be
the master secret, which mints capability ids; `--expect-head` pins the chain head
a verifier learned out of band, which is the only way to detect a truncated tail,
because any record-boundary prefix is a self-consistent shorter log. Chain only,
keyed, or pinned: the three modes answer different questions and the reply says
which one it answered.

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
