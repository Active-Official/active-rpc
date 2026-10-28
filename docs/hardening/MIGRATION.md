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
