# Architecture decisions

Accepted decisions below record explicit choices already made by the owner in
the planning conversation. They are not claims of successful implementation.

| ADR | Status | Decision |
| --- | --- | --- |
| [0001](0001-image-builder.md) | Accepted by owner | mkosi with pinned Debian stable |
| [0002](0002-storage-protection.md) | Accepted by owner | dm-verity A/B roots, LUKS2 data only |
| [0003](0003-data-recovery.md) | Accepted by owner | Unique per-device offline escrow with two-person access |
| [0004](0004-defer-git-commit-signing.md) | Temporary owner-approved exception | Defer Git commit signing during initial development, not boot/update signing |
| [0005](0005-qemu-verifier-anchor.md) | Accepted | The initial firmware verifier in QEMU is host-anchored only; no verified-boot claims until a protected-RO layout exists |
| [0006](0006-dev-key-hierarchy.md) | Accepted | Three-role development hierarchy (PK/KEK/image-signing) under gitignored `secrets/`; production custody remains a separate decision |
| [0007](0007-offline-varstore-enrollment.md) | Accepted | Offline variable-store enrollment: the `enroll` stage constructs the EDK II store host-side into the erased SMMSTORE region |
| [0008](0008-vboot-adoption.md) | Accepted | vboot protected-RW verification on the Q35 firmware: custom fmd, dev vboot keyset, `firmware-sign` and `check-firmware-vboot` |
| [0009](0009-pcr-policy-key-and-phases.md) | Accepted | PCR-policy signing key under `secrets/pcr/`, `enter-initrd`-only phase set, four-way independent verification in the `pcr-sign` stage |
| [0010](0010-per-device-luks2-data-volumes.md) | Accepted | Blank `FIREARC_DATA` in the factory image; per-device LUKS2 volumes born at provisioning; recovery credential under profile `secrets/`, escrow pending |

Implementation proposals in `PLAN.md` still require their stated feasibility and
security gates; do not treat a proposal as a validated component contract.
