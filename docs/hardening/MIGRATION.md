# Migrating from JSON or YAML

Active Infinity keeps the shape of a configuration document and changes the
representation: a canonical binary image, a content hash, structural secrets and
units. This guide maps the common cases.

## Migrating to `active-rpc` 2.0

The `ARP1` wire format does not change. One Rust API change is breaking:

- `Error::UnknownCapability` and `Error::Revoked` carry `CapToken` instead of
  `u128`. The raw bits stay internal; formatting prints a correlation id.
  Replace a `u128` match with `error.code()` (`rpc/unknown-capability`,
  `rpc/revoked`) or match `CapToken`.
- `Display for CapId` prints the correlation id. `CapId::hex()` remains the
  explicit raw-authority accessor for a deliberate transfer.

New conveniences are additive: `Metrics` and `Agent::metrics`, the refusal
events, `destroy_channel`, `promise_count`/`job_count`, `decode_capability_table_with`,
`LocalProcess::with_timeout`, and the `MAX_*` ceilings.

`LocalProcess::new` and `StdioTransport::spawn` now take authority over the
program identity rather than trusting the environment:

- `LocalProcess::new(program, args)` returns `Result<Self>` and refuses a
  relative or bare `program`. Pass `"C:\\Windows\\System32\\cmd.exe"` or
  `"/bin/sh"`, never `"cmd.exe"`: a bare name is resolved from the parent's
  `PATH`, so anything that can write an earlier entry would choose the binary
  the capability runs. The canonical path is pinned at construction, and
  `with_current_dir` pins the working directory (it also returns `Result` and
  refuses a relative directory). The pin is the content, not just the path
  (RPC-43): construction also records a BLAKE3 digest of the program's
  bytes, and every invoke re-hashes before spawning -- a binary replaced
  in place after construction is refused with `rpc/provider`
  (`process/program-changed`, `mcp/program-changed` for an MCP server),
  never silently re-pinned. A program that cannot be read is refused at
  construction.
- `StdioTransport::spawn` refuses a non-absolute `program` for the same reason.
- A bare `"*"` argument rule in `LocalProcess::new(program, args)` no longer
  admits any argument: it is a prefix of `""`, so it used to admit every
  argument — any file to a path-taking program, any command line to a shell —
  through metachar-free arguments the shell-syntax guard cannot see (RPC-40).
  A deployment that relied on `"*"` must either list the arguments exactly,
  use a non-empty prefix (`"echo*"`), or opt in explicitly with
  `LocalProcess::with_allow_any_arg()` — the opt-in is a deliberate statement
  that the program may receive arbitrary arguments, and the shell-syntax guard
  still applies to arguments admitted only through it. Construction prints a
  warning to stderr whenever a bare `"*"` rule is present, so the change is
  visible at startup rather than at the first refused call.
- Minting a capability over an MCP, HTTP or process tool now attaches the
  provider's tool policy by default (RPC-41). A mint without an explicit
  policy used to skip the method/arg-byte gate entirely -- only the method
  set and the budget applied -- so a 200 KiB argument to an MCP tool sailed
  through. The minted capability now carries the provider's policy
  (`McpSession::policy`, `HttpTool::policy`, `LocalProcess::policy`):
  an oversized argument is refused with `rpc/tool-policy`, and a process
  tool minted without a policy can now spawn (its policy grants process
  execution), where before every call was refused for want of the grant.
  An explicit policy supplied at mint still wins, narrower or wider. One
  edge: an MCP server advertising more than 64 tools refuses a
  policy-less mint (`rpc/invalid-argument`, "a capability grants too many
  tools") -- mint with an explicit policy naming only the tools the
  capability may use.
- The control-plane MCP now reads plane responses with a 1 MiB ceiling
  and marks embedded-plane answers `degraded` (RPC-42). A plane
  response larger than 1 MiB used to be read whole -- W2's probe
  carried a 20 MB `/metrics` body back through `cp_metrics` -- and is
  now refused with an error (`control-plane response exceeds the
  1048576-byte ceiling`, JSON-RPC -32603), never truncated. A legitimate
  plane snapshot is tens of KiB and is unaffected. And when the attach
  target is unreachable the MCP used to fall back to an empty embedded
  plane and answer as if real; every answer from the embedded plane now
  carries `"degraded": true` inside the answer text, so offline `--mcp`
  use still works but is visible as degraded.
- A Unix timeout now signals the child's whole process group through the
  `killpg` syscall, and only when the group is still provably the child's
  own (RPC-43): a leader that exited long ago may have had its pid reused
  as a new process-group leader, and a bare `-<pid>` signal would take an
  unrelated group down with it. A Windows timeout terminates the job
  object holding the whole tree (XPL-RPC-04), not `taskkill /T` -- the
  job has been the mechanism since XPL-RPC-04, and this bullet previously
  said otherwise. Descendants do not outlive the call on either platform.

Promises are retained while a `PromiseHandle` is alive. Dropping the handle makes
the settled record eligible for trimming after the next drain; a handle never
loses a result it can still read.


## Values

| JSON / YAML | Active Infinity |
|---|---|
| object | `Table` (field order canonicalized by name) |
| array | `Array` |
| string | `Str` |
| integer | `Int` |
| float | `Float` |
| boolean | `Bool` |
| null | `Null` |
| `"1500ms"` | `Quantity { value: Int(1500), unit: Milliseconds }` |
| a password or token | `Secret(SecretBytes)` — never `Str` |
| a schema or type | `SchemaField`, `SchemaTable`, `SchemaArray` |

Do not encode a secret as a string and rely on a naming convention. The secret
kind is the taint; the projections and `Debug` redact it, and equality never
reveals it.

## A small document

YAML:

```yaml
app:
  name: checkout
  port: 8080
  timeout: 1500ms
  token: "${env:CHECKOUT_TOKEN}"
```

Rust:

```rust
let mut module = InfinityModule::new();
let name = module.push(Inode::Str("checkout".into()));
let port = module.push(Inode::Int(8080));
let ms = module.push(Inode::Int(1500));
let timeout = module.push(Inode::Quantity { value: ms, unit: UnitTag::Milliseconds });
let locator = module.push(Inode::Env { name: "CHECKOUT_TOKEN".into(), default: None });
let token = module.push(Inode::SecretRef { locator });
let app = module.push(Inode::Table {
    fields: vec![
        ("name".into(), name),
        ("port".into(), port),
        ("timeout".into(), timeout),
        ("token".into(), token),
    ],
});
let root = module.push(Inode::Table { fields: vec![("app".into(), app)] });
module.set_root(Some(root));
let image = encode(&module)?;
assert!(validate(&image).is_ok());
```

## Operational differences

- The content hash is the identity. Compare hashes, not serialized text.
- `canonical` in the header is a claim. A consumer that relies on identity calls
  `validate_canonical`, which re-encodes and compares.
- Schema changes are explicit nodes; migrating a document is a `Patch` node, not
  a text rewrite.
- Secrets cannot be projected. A redacted JSON view is for humans and logs; the
  binary image is the transfer format.
- Units are explicit. A bare number is an `Int`; a duration is a `DurationMs` or
  a `Quantity`.

## Migrating an RPC service

| JSON-RPC / gRPC | Active RPC |
|---|---|
| method name | capability method string |
| bearer token | capability handle (possession is authority) |
| per-request authorization | attenuation at mint time, revocation at dispatch |
| retries with a request id | promise id plus single settlement |
| streaming | lanes and channels |
| deadline | `Budget::max_wall_ms` |

Start with `examples/loopback.rs`. Mint one capability per caller and attenuate
it; never forward the root capability.
