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
