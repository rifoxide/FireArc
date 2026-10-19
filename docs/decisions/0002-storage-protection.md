# ADR 0002 — verity A/B roots; encrypt persistent data only

**Status:** Accepted by owner during planning; recorded 2026-10-19.

## Decision

Leave the ESP, signed UKIs, root A/B and verity trees unencrypted. Authenticate
the boot chain and mount each root read-only through dm-verity, including a full
protected-root scan before normal readiness. Encrypt persistent data with LUKS2;
authorize normal unlock using a tested TPM2 policy.

## Consequences

Public release artifacts must not contain device secrets. Root-slot encryption
is deferred, not partially implemented. A/B root rollback does not roll back data,
firmware or TPM state; schema/enrollment compatibility is a separate gate.
Encryption does not itself authenticate writable configuration or prevent replay.

References: C-04/C-05/C-06; `PLAN.md` Sections 4.3–4.6. Final GPT capacities and
TPM PCR phase authorization still require their implementation tests.
