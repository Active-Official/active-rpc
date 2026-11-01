# ADR-0010 - Durable versus ephemeral capabilities

**Status:** accepted (2026-10-30). Accepted under AIM-PROP-2026-10 C-5.5.

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
carries no capability id and no secret; ids derive from the kernel secret and
mean nothing elsewhere. `Agent::export_capability` exports only a live `Durable`
capability, only through the handle that owns it, and refuses an ephemeral one.

Two fields make the record a credential rather than a suggestion:

- `record_id` is a secret-derived identity for the capability. It survives an
  export/restore round trip inside one authority domain and is what a
  revocation tombstones: `revoke` inserts the record id of every capability in
  the doomed subtree, and `restore_capability` refuses a tombstoned id with
  `rpc/revoked`. A record exported before the revocation therefore cannot
  revive the authority.
- `seal` is a keyed Blake3 MAC over every other field, keyed by the deployment
  key set with `Agent::set_record_seal_key`. Without a key the kernel exports
  and restores nothing (`rpc/persistence`). With one, an edited, fabricated or
  foreign record fails the check before any field is read, and the comparison
  is constant-time. The key must be deployment-provided: a per-process kernel
  secret cannot verify a record written by another process.

### Restore

`Agent::restore_capability(record, admitted_peer)` is a **re-mint**, never a
resurrection:

- the id is new (and differs even in the same kernel);
- the authority is exactly the record's, with the record's absolute deadline as
  the remaining TTL, so a restored capability cannot outlive the original;
- the capability is bound to the admitted peer. A record bound to another peer
  is refused with `rpc/identity`. Export itself refuses a capability that names
  no peer: a credential that restores for anybody is not a credential, and an
  earlier unbound export would escape a later `introduce_to`;
- two restores of the same record are refused (`rpc/persistence`): one while
  a copy is live, because revocation walks ids and could not reach an
  independent copy; and one after the copy is dropped, because the record is
  spent. A kernel remembers the ids it restored, so dropping the handle does
  not make the credential restorable again in that process. A restart starts
  with an empty set, which is why the kill list has to be replayed.

Restore is refused (`rpc/persistence`) unless the agent enabled durable
capabilities, a seal key is configured and the seal verifies, and the provider
is registered. A tombstoned record id is `rpc/revoked`.

### Consumption and reservation

Export is a transfer, not a copy, and the kernel treats it as one:

- a record is consumed by its export. Exporting the same capability twice is
  `rpc/persistence`, and the id stays consumed after the capability is dropped,
  so one credential cannot produce two records;
- the record carries the minimum remaining budget of the capability *and* every
  ancestor, and that grant is reserved on the same chain
  (`BudgetMeter::check_reserve`/`reserve`). The local subtree can no longer spend
  what the record now holds, so restoring a child cannot outspend the parent it
  was derived from;
- a refusal that happens before a record is handed out (an empty path scope, no
  seal key, an unbound capability) costs nothing: the grant is not reserved and
  the id is not consumed;
- a record whose budget disables a ceiling is refused as `rpc/persistence`, not
  as a caller argument error;
- both id sets are bounded (`MAX_RECORD_IDS`, 65 536). Past the ceiling a new
  export or restore is refused with `rpc/budget-exceeded` rather than growing
  the set without bound.

A tombstone is a kill switch, not only a restore filter: `tombstone_record`
revokes every live capability carrying that record id (and its subtree), so a
restore that ran before the kill list was replayed cannot outlive the replay.

### Startup order

The kill list is replayed with `tombstone_record`. A deployment that also
restores records at startup must replay first; the kernel makes the later
tombstone reach a live copy, but an unrestored credential is the only one where
the order is invisible.

### Object identity (residual)

`object` is the provider's local object id, not a name. A restore re-mints the
recorded authority against whatever the registered provider calls that id, so a
provider must keep object ids stable across restarts of the same deployment; a
registration order that changes maps a restored credential onto a different
object. A name-based object identity would be a record format change.


Tombstones live in memory, so a process restart would otherwise resurrect every
record exported before the kill switch. A deployment replays its persistent kill
list with `Agent::tombstone_record` at startup and can read the set back with
`record_is_tombstoned` and `record_tombstone_count`. Only a durable record is
tombstoned (an ephemeral one can never be restored) and the set has a ceiling: a
new durable mint is refused rather than evicting a tombstone, because eviction
is fail-open. A record whose deadline
has passed is refused, and so is one whose clock mode differs from the restoring
kernel's (ADR-0015).

### Why this is safe

A record alone is not authority: using it requires a deployment that opted into
durable capabilities, holds the seal key, and admitted the peer the restore
names. The record is metadata, so it can be stored in a configuration system; it
must still be protected like an ACL file, because it describes exactly what an
admitted peer may do.

### Evidence

`tests/capability_record_tests.rs`: round trip, ephemeral refusal, policy
refusal, passed deadline, cross-peer refusal, unknown provider, malformed and
oversized records, and deadline preservation across restore.
