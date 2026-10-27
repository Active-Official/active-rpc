# Contributor Code of Conduct

## Our commitment

Active RPC carries authority between agents. Contributors are expected to treat
authority, secrets and other people's time with the same care the code does.

## Expected behaviour

- **Evidence over assertion.** A change claims what its tests show.
- **Respect the invariants.** No ambient authority, monotone attenuation,
  fail-closed framing, no secret bytes on the wire. If a feature needs one of
  those weakened, the feature is wrong.
- **Review in good faith.** Critique code, not people.
- **Small, explainable changes.** A structural change needs an ADR and a test.

## Unacceptable behaviour

Harassment, discrimination, personal attacks, publishing private information, or
knowingly shipping a change that weakens a security guarantee (a bypassable
budget, a forgeable capability, a leaked secret, a silently accepted malformed
frame).

## Scope

Repository, issues, pull requests, and any space where someone represents the
project.

## Enforcement

Report concerns to the maintainers listed in `SECURITY.md`. Reports are handled
privately, and responses are proportional and documented internally.

## Attribution

Adapted for this project from the spirit of the Contributor Covenant v2.1.
