# Active risks and decisions

Recorded 2026-10-19. Owners below are engineering roles, not invented personnel
assignments. The program owner must assign named reviewers before closing gates.

| ID | Severity | Risk / dependency | Owner role | Blocking gate / closure evidence |
| --- | --- | --- | --- | --- |
| R01 | Critical | No physical firmware root/fuse/protection evidence | Firmware/security | G13; per-sample FireArc authority, flash/ME/root report |
| R02 | High | vboot + Dasharo EDK II + SMMSTORE/layout feasibility untested | Firmware | Firmware-verification part of G2; modified mutable firmware rejected before execution |
| R03 | High | Historical pins are compatibility inputs, not complete provenance/CVE approval | Build/security | G2/G11; source/authentication review and deliberate refresh |
| R04 | High | Signed snapshot/tools closure and rootless mkosi smoke implemented; portable host Python/kernel/helpers, appliance package closure and trust/CVE review remain incomplete | Build/platform | G1/G3; authenticated reproducible appliance builder and complete package closure |
| R05 | High | Host systemd 262 research stub differs from systemd 257 userspace | Platform/TPM | G3/G5; aligned/qualified versions and rollback token/phase compatibility |
| R06 | High | RAUC's native EFI backend is not systemd-boot slot integration | Update | G6/G7; reviewed custom backend, explicit activation and health/counter tests |
| R07 | High | Shared FAT ESP can break both candidate and known-good availability | Platform/test | G7/G12; storage-fault/power-cut campaign or redesign |
| R08 | High | Pre-Linux image denial is outside Linux watchdog coverage | Firmware/test | G7; actual automatic next-entry/reset behavior, not host termination |
| R09 | High | PCR7 transitions, PCR11 boot phases and enrollment formats can strand data | TPM/security | G5/G10; both slots plus key/firmware transitions tested with recovery |
| R10 | High | Shared-data migration can make old root unusable | Platform | G7; compatible/transactional schema migration and rollback test |
| R11 | High | Signatures alone permit old valid images; revocation differs from rollback | Security/firmware | G10; install/version plus authenticated revocation/protected-epoch design |
| R12 | High | Recovery could expose a shell/unlock/reset bypass | Security | G9; restricted signed recovery, operation-bound one-time authorization and separate escrow |
| R13 | High | Old LUKS headers/escrow complicate revocation and secure reset | Security/operations | G5/G9; access, rotation, retention and reset procedures |
| R14 | Medium | Full-root scan may miss timing targets | Platform/performance | G12/G13; measure/optimize without silently weakening coverage |
| R15 | Medium | Hardware/HSM/legal approval/business-design document unavailable | Program/hardware/release | Relevant G0/G11/G13 portions remain pending with explicit dependency |
| R16 | Medium | Git commit signing temporarily deferred by owner, ADR 0004; no identity configured | Owner/release | Does not block current development; revisit GOV-02 before G11/release, with no automatic key generation or global Git changes |
| R17 | Medium | Software TPM state is cloneable and private | Platform/security | Preserve 0700 custody; no physical non-exportability claim or public state export |
| R18 | High | Attaching TIS to inherited firmware produces two ACPI TPM probe entries sharing the same resource; second probe reports `-EBUSY` | Firmware/TPM | Resolve in source-built firmware before G5; one intended TPM device, correct table ownership/handoff and replayed logs |

## Review rules

- Record FAIL, BLOCKED, historical-only and HARDWARE-PENDING separately from PASS.
- No source rebuild, release, attestation or hardware gate is closed by the
  research regression runner alone.
- This task performs no vendor-image acquisition; counsel/owner must resolve the
  PDF's no-dumping/private-recovery-backup conflict before physical work.
- Work may continue on independent QEMU inputs/tests while external approvals
  remain pending. No hidden weakening of a gate to report progress.
