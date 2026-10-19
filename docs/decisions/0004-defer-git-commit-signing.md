# ADR 0004 — defer Git commit signing during initial development

**Status:** Temporary exception approved by owner on 2026-10-19.

## Decision

The owner explicitly requested: "skip commit signing for now". Do not block
local implementation on a Git signing identity, generate a signing key, or
change global Git configuration. Commits, if separately requested, may be
unsigned during this temporary development exception.

## Boundaries and consequences

- GOV-02's signed-commit requirement is deferred, not satisfied or removed from
  the authoritative R&D requirements. Revisit signing before release/CI gate G11.
- This is not authorization to skip firmware, UEFI/systemd-boot/UKI, PCR-policy,
  RAUC, recovery or release-artifact signatures.
- It does not authorize additional private-key access or key generation.
- It does not by itself request a commit or push; current implementation work
  remains local until publication is requested.
- No Git signing identity/key is created by this decision.
