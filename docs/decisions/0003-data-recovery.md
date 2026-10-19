# ADR 0003 — per-device escrow recovery

**Status:** Accepted by owner during planning; recorded 2026-10-19.

## Decision

Generate a separate high-entropy recovery credential for each device's LUKS2 data.
Escrow it offline with audited, two-person retrieval. This supports deliberate
recovery after TPM/device failure; no shared factory/fleet-wide recovery key.

## Consequences

Normal A/B unlock must not require escrow or network access. Disk transplant to
another TPM must fail unattended, while approved escrow recovery remains an
explicit exception. Never place recovery material in logs, command arguments,
Git, firmware, images or general artifact storage. Recovered credentials and
escrow records need a reviewed rotation/retention procedure.

Old LUKS header backups can restore old keyslots; slot deletion alone is not a
complete revocation/erase guarantee. Recovery diagnostics, destructive factory
reset and sensitive-data unlock require separate authorization.

References: C-06/C-08; `PLAN.md` Phases 5 and 9. No recovery secrets are generated
by static build checks or an unprovisioned image.
