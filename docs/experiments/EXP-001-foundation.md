# EXP-001 — independent Q35 research baseline and persistent-state foundation

**Date:** 2026-10-19. **Workspace:** `/home/rifat/projects/firearc`.
**Status:** Baseline regression and final persistent-TPM runner smoke retests PASS; qualification gates remain partial.

## Purpose and boundary

Start PLAN Phases 0/1 without replacing the successful research or claiming the
final appliance. Reuse the approved EXP-029 public artifacts, not its launchers,
private keys, original writable flash or original overlay disks.

Coverage: GOV-01, input/provenance portions of GOV-02/TEST-01, historical B-04/C-04
regression and laboratory state management. No source-rebuild, systemd-boot,
LUKS2, RAUC, automatic rollback, attestation or physical-root gate is passed here.

## Inputs and environment

- The supplied R&D PDF matches SHA-256
  `bab9389d81b9c5bd85b023551fb466ad1d41c7ee0bdb5c9996feefbe56346c49`.
- Five complete pinned historical manifests and 582 listed files verified.
- Nine inherited source HEADs match their commits and have no tracked changes;
  upstream publisher signatures remain unverified.
- Thirteen allowlisted public files imported; private signing-key trees were
  neither visited nor read. Import paths/pins are in `locks/research-baseline.json`.
- QEMU/QEMU-img 11.1.2, swtpm 0.10.2, debugfs 1.47.4 and veritysetup 2.8.8;
  exact executable hashes in `locks/lab-tools.json`. Dynamic-library/build
  provenance is not established by those binary hashes.
- Linux x86-64, Python 3.14.8, Q35 `pc-q35-11.1,smm=on`, TCG, `qemu64`, 2 vCPUs,
  1536 MiB, no NIC, display disabled, serial-only automated evidence.
- Inherited source-built coreboot/EDK II ROM, directly launched signed UKI and
  768 MiB Debian 13 root/tree. systemd-boot is not in this fixture's boot path.

All test artifacts/state are under ignored private `run/`/`artifacts/`. Public
summary/hashes are recorded here; raw TPM state is never exported or hashed.

## Offline checks

`just check` passes **46 tests**, the specification/lock check and repository
credential-pattern screening. Tests cover malformed/pinned manifests, traversal,
symlinks, duplicate names, chunk-boundary private-PEM detection, no-overwrite
evidence/imports/devices, exclusive locks, wrong tool/backing pins, missing TPM
state, boot-report completeness, backend shutdown races, local QMP framing,
document links and Python syntax. No VM/root/daemon/network is needed for these
unit tests. Credential screening is not proof against every possible secret.

## Baseline regression results

Evidence path prefix: `run/devices/baseline-a/boots/`.

| Label | Expected/observed result | Recorded seconds |
| --- | --- | ---: |
| `good-a` | Full Secure Boot/root acceptance, clean poweroff: PASS | 29.488 |
| `good-b` | Second cold boot, same flash/overlays, distinct boot ID: PASS | 26.490 |
| `data-executable-a` | Modified executable protected block refused before mapping: PASS | 13.686 |
| `data-unused-a` | Modified unused-but-protected block refused before mapping: PASS | 21.262 |
| `hash-tree-a` | Modified tree refused before mapping: PASS | 19.903 |
| `replacement-pair-a` | Coherent substituted pair validates its own hash on host, but signed authority rejects it: PASS | 21.621 |
| `unsigned-a` | Unsigned UKI refused before kernel execution: PASS | 10.287 |
| `wrong-a` | Wrong-key UKI refused before kernel execution: PASS | 7.290 |
| `tampered-a` | Modified signed UKI refused before kernel execution: PASS | 7.086 |
| `final-good-a` | Original valid path remains usable after negatives: PASS | 26.891 |

Positive reports require the exact db, signed command line, expected live
verity digest/salt/geometry, full-scan/mapping stage order, read-only root mount,
lockdown, unique kernel boot ID and clean guest poweroff. They are not accepted
from `FIREARC_ROOT_READY` alone. The audited guest acceptance script also refuses
a root write before reporting readiness.

Each negative uses a new run label and per-run mutations; originals remain
unchanged. Normal device flash/overlays persist, unlike the original launcher's
fresh-flash-every-run profile. No weakened signature/hash check is used.
Firmware-negative runs are **host-stopped after observed denial**; they do not
demonstrate unattended fallback.

Every listed run passed post-run import rehash, root/hash content comparison,
SMMSTORE-only flash-difference and owned-process reaping checks.

Recorded intervals include harness staging/process teardown but exclude final
input rehash/content comparisons; concurrent VMs also contend for host resources.
These numbers are **not** power-on-to-forwarding or update-downtime measurements.

## Software TPM and state-loss guard

`tpm-smoke-a` passed two cold boots (`first-a`: 44.748 s; `second-a`: 41.348 s),
retaining its per-device flash, disks and private swtpm directory. Both boots
show Linux detecting TPM 2.0 and firmware/EFI TPM log pointers. No PCR replay,
EK/AK enrollment, data policy or remote-quote qualification follows from that.

A guard test on separately created `tpm-smoke-b` temporarily withheld its owned
state file **without reading its contents**. Ordinary boot failed before the
guest-execution stage, did not recreate state and did not start a VM. The original
file was restored without overwriting any replacement.

Guard evidence: `run/guards/missing-tpm-state-a.json`.
Its SHA-256 is `e86605efa74adfe80fe1486834a8396381fd90914b8d61b62e3d973c55f920dd`.

The runner now initializes swtpm state only during explicit `baseline-new --tpm`.
Ordinary boots require the existing nonempty 0600 state file, owned by this user,
and refuse a missing/empty/symlinked state rather than silently create a new TPM.
No HSM or real hardware TPM is claimed.

### Retained failed run and correction

`tpm-smoke-b/boots/first-b` is retained as **FAIL**. The guest completed its full
acceptance report and clean poweroff, but the runner treated swtpm's normal exit
just before QEMU became waitable as an unexpected backend failure. Live local
QMP `status` had returned `running`; its requested operation is in the evidence.

The correction permits only a zero-status backend exit followed by QEMU exit
within five seconds, then still requires the full guest report/exit validation.
An abnormal backend exit or still-running guest fails. Four unit tests cover
this distinction. The failed evidence is not overwritten/reclassified; new-label
retests are required.

Fresh-label retests on the **same**, unreset device passed:

| Label | Result | Recorded seconds |
| --- | --- | ---: |
| `second-b` | TPM 2.0 detected, full root acceptance, live QMP status/journal, clean QEMU/swtpm exit: PASS | 41.544 |
| `third-b` | Second cold boot with distinct boot ID, preserved state and clean exits: PASS | 41.145 |

Both results explicitly retain `tpm_duplicate_probe_warning=true` and
`tpm_policy_qualified=false`. The raw private state was not read or reinitialized.
All three research-device active records are absent after their processes exited.

## Finding R18 — duplicate ACPI TPM resource

TPM attachment exposes both `MSFT0101:00` and `MSFT0101:01` for the same TIS
resource. The first detects TPM 2.0; the second logs `-EBUSY` / failed probe.

Preserve and resolve this in fresh firmware before measured/data-policy gates.
Possible table producers exist in coreboot's `src/drivers/pc80/tpm/tis.c` and
EDK II's `SecurityPkg/Tcg/Tcg2Acpi/Tpm.asl`; actual table ownership and event-log
handoff still require analysis. Do not suppress the warning and claim G5.

## Historical evidence manifest pins

The values below pin each run's `SHA256SUMS`; commands, tooling snapshots,
console, mutations, results and tool/input hashes are listed inside it.

| Run | SHA-256 of evidence manifest |
| --- | --- |
| `baseline-a/good-a` | `1a32f53a9f5f9caa02864ff53db3f812a5f41b7071b7fb7e1ae4d85e1bfbcb8c` |
| `baseline-a/good-b` | `149ef82ebba82e8b6ccd69d588070a55020495e30be6880ffeaf8f325be495e3` |
| `baseline-a/data-executable-a` | `a00febdd3ea356ec81007b448052469e0d65f8a647a2917bdd31307f5b34ce57` |
| `baseline-a/data-unused-a` | `c54bcdcc18ab277f977c6b6c6332b84a276102c28b21875ebd8226a68a7d96f6` |
| `baseline-a/hash-tree-a` | `975e793e42b3492275098e5c465c845f812ff975a004dda4159376e5b30fde12` |
| `baseline-a/replacement-pair-a` | `6012fe6c4f0857f99197a3c0908cb710edd31608c3fdb902fc7990cefac51fd5` |
| `baseline-a/unsigned-a` | `f7e455a9f2bb9e15b8c5ca32e8a4ab01f0360366bf5da85c90a5eef175694cf9` |
| `baseline-a/wrong-a` | `2c049b2d756cd4511624092f10965bdf385b1700f2eaabeaaadadebadc74964c` |
| `baseline-a/tampered-a` | `684e57d05513bd7b7d1faa92941fc79449b13a79bf1d2782a418d0651f2768fd` |
| `baseline-a/final-good-a` | `65f9608a2faa1df5bbee442b1e5dd311bf53a90e0c0625c1633d776ea84749c5` |
| `tpm-smoke-a/first-a` | `e91a2db03aa56ede8070f4b0ca477d880f1dd1ed365c617760755d4adbdea276` |
| `tpm-smoke-a/second-a` | `3c318df20cd77e0191259ecbe539ccade06d802d54b4b0153fdd16150c52e192` |
| `tpm-smoke-b/first-b` (**retained FAIL**) | `396c0965a6a0b99dce60d5e1a2ccb4fd7218556f9a4af85b436b58ab43a5d961` |
| `tpm-smoke-b/second-b` | `53482e70358e716fb913493caa2cfb02432dddac623f9d89442f65e92ac4bd45` |
| `tpm-smoke-b/third-b` | `a9842aac8816d2cdff446a8d17db78a38b8d58ec80b8f2c0c9d7343b48dfffed` |

Manifests pin recorded evidence; they do not make these local unsigned records
an independent attestation or a reviewed production release. Actual working
tooling is copied per run, rather than falsely attributed to the earlier plan
commit `47c81ba`.

## Reproduction and next steps

Use [the laboratory runbook](../lab.md) with fresh device/evidence names. Do not
wipe or reset the existing tests to rerun them. Validate the complete pinned
reference first; no private key is needed.

Next: the portable mkosi/Debian builder,
aligned systemd tools and fresh source-built firmware/root. Fix R18, introduce
signed systemd-boot and only then qualify PCR policies/LUKS2 and RAUC/A/B.
G0 owner/security review, portable G1 build inputs and all later security gates
remain open as recorded in [progress](../progress.md).
