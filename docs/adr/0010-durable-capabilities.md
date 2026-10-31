# ADR 0010 — Durable versus ephemeral capabilities

Status: accepted for AIM-PROP-2026-10 C-5.5.

## Decision

A capability carries a local `CapPersistence` policy:

- `Ephemeral` (default): the capability dies with the process.
- `Durable`: eligible for a deployment-provided secure restore path.

Durable minting is refused unless the agent explicitly enables it with
`Agent::set_durable_capabilities(true)`. The policy is local authority metadata;
it is not a wire descriptor field and never travels in `CapDescriptor`.

Attenuation never promotes persistence. A durable child of an ephemeral parent
is safely downgraded to ephemeral; a durable parent may produce durable
children. The kernel does not write raw capability ids to disk. A durable store
must be supplied by the deployment, must protect the bearer token like a private
key, and must re-import through the normal registry/attenuation checks.

## Why

Durable capabilities are bearer credentials at rest. Silently persisting them
would turn a process-local authority bug into a long-lived credential leak.
Explicit opt-in plus a local-only policy keeps the default fail-closed.

## Consequences

- Restoring a durable capability is a deployment feature, not an automatic
  kernel behavior.
- A durable cap is still revocable and still attenuates monotonically.
- The wire format is unchanged; a remote peer cannot request durability.

## Addendum (2026-10-31) — minimal restore profile

The original decision left restore entirely to the deployment. This addendum
defines the smallest profile the kernel itself supports, so a deployment does
not have to invent a format.

### Record

`CapabilityRecord` (`active-rpc/capability-record/1`) is the authority metadata
of a durable capability: provider name, object, methods, budget, read-only,
redaction, path scope, topics, tool policy, binding and absolute deadline. It
carries **no id and no secret**; ids derive from the kernel secret and mean
nothing elsewhere. `Agent::export_capability` exports only a live `Durable`
capability and refuses an ephemeral one.

### Restore

`Agent::restore_capability(record, admitted_peer)` is a **re-mint**, never a
resurrection:

- the id is new (and differs even in the same kernel);
- the authority is exactly the record's, with the record's absolute deadline as
  the remaining TTL, so a restored capability cannot outlive the original;
- the capability is bound to the admitted peer. An unbound record becomes bound;
  a record bound to another peer is refused with `rpc/identity`.

Restore is refused (`rpc/persistence`) unless the agent enabled durable
capabilities and the provider is registered, and refused once the deadline has
passed.

### Why this is safe

A record alone is not authority: using it requires a deployment that opted into
durable capabilities *and* a transport that admitted the peer the restore names.
The record is metadata, so it can be stored in a configuration system; it must
still be protected like an ACL file, because it describes exactly what an
admitted peer may do.

### Evidence

`tests/capability_record_tests.rs`: round trip, ephemeral refusal, policy
refusal, passed deadline, cross-peer refusal, unknown provider, malformed and
oversized records, and deadline preservation across restore.
