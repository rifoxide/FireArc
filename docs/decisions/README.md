# Architecture decisions

Accepted decisions below record explicit choices already made by the owner in
the planning conversation. They are not claims of successful implementation.

| ADR | Status | Decision |
| --- | --- | --- |
| [0001](0001-image-builder.md) | Accepted by owner | mkosi with pinned Debian stable |
| [0002](0002-storage-protection.md) | Accepted by owner | dm-verity A/B roots, LUKS2 data only |
| [0003](0003-data-recovery.md) | Accepted by owner | Unique per-device offline escrow with two-person access |
| [0004](0004-defer-git-commit-signing.md) | Temporary owner-approved exception | Defer Git commit signing during initial development, not boot/update signing |

Implementation proposals in `PLAN.md` still require their stated feasibility and
security gates; do not treat a proposal as a validated component contract.
