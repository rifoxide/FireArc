# FireArc secure boot and atomic-update implementation plan

**Date:** 2026-10-19  
**Status:** Implementation started: Phase 0/1 foundation. See [progress](docs/progress.md); no completed appliance is claimed.
**Primary specification:** `FireArc_R-D_Plan—Technical_Team.pdf`, dated 2026-10-17, all 13 pages.  
**Implementation workspace:** `/home/rifat/projects/firearc`  
**Read-only research reference:** `/home/rifat/projects/project_firearc`  
**Initial target:** x86-64 QEMU Q35; physical reference units and ODM hardware are unavailable.

## 1. Objective and approved decisions

Implement and qualify this appliance lifecycle:

```text
pinned sources and authenticated Debian packages
  -> reproducible firmware and OS builds
  -> controlled signing and provisioning
  -> coreboot + EDK II UEFI
  -> FireArc Secure Boot
  -> FireArc-signed systemd-boot
  -> FireArc-signed unified kernel image (UKI), slot A or B
  -> trusted initramfs verifies the selected root
  -> read-only dm-verity root
  -> TPM-authorized unlock of LUKS2 persistent data
  -> hardened Debian userspace
  -> appliance health assessment
  -> signed RAUC update to the inactive slot
  -> bounded trial boot, acceptance or unattended rollback
  -> authenticated recovery when necessary
```

### 1.1 Decisions confirmed with the user

| Item | Decision |
| --- | --- |
| Development platform | QEMU Q35 until hardware arrives. |
| Firmware | Source-built coreboot with an EDK II UEFI payload; reuse the successful Dasharo research dependencies initially. |
| OS image builder | **mkosi**. Existing mmdebstrap research is a reference, not the new top-level image pipeline. |
| OS family | Minimal Debian stable, as required by the PDF. |
| Boot manager | **systemd-boot**, followed by a signed UKI; not direct-UKI boot as the final path. |
| Immutable OS | Two read-only, dm-verity-protected root slots. |
| Encryption now | **Persistent data only**, using LUKS2 and TPM2 enrollment. |
| Encryption later | Root-slot encryption is deferred, not part of this implementation. |
| Updates | **RAUC**, not Mender. |
| Data recovery | Unique per-device recovery credential, escrowed offline with audited, two-person access. |

The ESP, UKIs, root images and verity trees remain unencrypted. Their integrity must be authenticated by the boot chain. No device secret may be embedded in those public artifacts.

### 1.2 Scope boundaries

This is principally **Workstream B: boot chain and firmware** and **Workstream C: FireArc OS base**. Include the interfaces needed by A and H, and a minimal forwarding test fixture needed to measure the PDF's boot/update targets.

Do not expand this task into the full firewall product, IPS/NDR/ML, Firewalla study, cloud console, mobile app, billing, fleet management or production remote-support system. A small test attestation server is required by B; it is not a cloud console.

Maintain separate completion labels:

1. **Research baseline reproduced:** the existing EXP-029 behavior is reproduced without weakening its checks.
2. **QEMU OS lifecycle qualified:** signed systemd-boot/UKIs, verity, encrypted data, RAUC, health checks, rollback, recovery and test attestation pass on persistent Q35 machines.
3. **QEMU firmware-verification model qualified:** any claimed verification of mutable coreboot/payload regions is separately demonstrated, rather than inferred from Secure Boot.
4. **Physical platform qualified:** actual reference units pass firmware-root, TPM, flash, recovery and power-loss tests.

Do not call the whole R&D program complete when only this B/C subset is complete.

## 2. Requirements traced to the R&D PDF

Use these IDs in architecture decisions, tests and review reports.

| ID | PDF requirement | Location | Planned coverage |
| --- | --- | --- | --- |
| GOV-01 | Independent development, public/open-source inputs, isolated lab | pp. 1–3 | Phases 0–1; no vendor code/configuration copying. |
| GOV-02 | Signed commits, reproducible CI builds, artifact storage | p. 3 | Phases 1 and 11. |
| B-01 | Determine platform-root/Boot Guard ownership | p. 5 | Threat model now; actual fuse/key inspection in Phase 13. |
| B-02 | Self-built coreboot + UEFI, boot and recovery | p. 5 | Reuse EXP-029; Phases 1–2, 10 and 13. |
| B-03 | Record ME/CSME state and decide disable/HAP policy | p. 5 | Hardware checklist only; not emulated by Q35. |
| B-04 | FireArc PK/KEK/db, remove unrelated vendor trust, reject unsigned/modified UKIs | p. 5 | Phases 2 and 4; negative tests throughout. |
| B-05 | PCR measurements and a TPM quote verified by a test server | p. 5 | Phases 5 and 8. |
| B-06 | Signed firmware delivery and failed-update recovery | p. 6 | Phase 10; hardware requalification in Phase 13. |
| B-07 | UART/SPI/USB tamper assessment and mitigations | p. 6 | Virtual boot-policy tests now; physical tests in Phase 13. |
| B-08 | Offline root, HSM signing, two-person release, reproducible firmware CI | p. 6 | Phases 2 and 11; software-only custody must be labeled laboratory-only. |
| C-01 | Minimal Debian stable, mkosi/debos, pinned snapshot, identical rebuild hashes | p. 6 | mkosi selected; Phases 3 and 11. |
| C-02 | Maintained kernel, FireArc configuration, reduced drivers/filesystems, lockdown | p. 6 | Phase 3; test on each physical model later. |
| C-03 | Signed UKI and systemd-boot | p. 6 | Phase 4. |
| C-04 | Read-only dm-verity root; corruption causes refusal and fallback | p. 6 | Phases 3–4 and 7. |
| C-05 | A/B updates, health checks and automatic rollback | p. 6 | RAUC; Phases 6–7 and 12. |
| C-06 | TPM-sealed LUKS2 data; disk moved to another device unreadable | p. 6 | Phase 5; exception is explicitly authorized escrow recovery. |
| C-07 | AppArmor, parser seccomp, non-login service users, auditd, CIS assessment | p. 6 | Phase 11. |
| C-08 | Factory reset, serial recovery, TPM-bound one-time break-glass | p. 6 | Phase 9. |
| C-09 | CycloneDX SBOM, license scan, GPL source offer | p. 6 | Phase 11 and every release. |
| PERF-01 | Forwarding within 60 seconds of power-on | p. 7 | Phase 12; real packet forwarding, not merely a userspace-ready marker. |
| PERF-02 | Update downtime under two minutes | p. 7 | Phase 12; separate successful-update downtime from broken-update recovery time. |
| TEST-01 | Reproducible runs with unit, firmware, OS and test-input versions | pp. 11–13 | Evidence format in Section 10. |
| EXIT-01 | Reviewed outputs and named, owned risks for unmet requirements | p. 13 | Gates and final handoff checklist. |

**Interpretation notes:**

- PCR stability is conditional on the firmware, boot path, keys, platform configuration and measurement phase. Do not assume every PCR 0–7 is invariant or changes on every modification.
- An unfused Boot Guard configuration permits development but is not itself a hardware-enforced root of trust.
- An ODM-owned Boot Guard root means FireArc lacks independent authorization; ODM cooperation could authorize a FireArc image. Require actual FireArc control, not just the ability to obtain one signed image.
- The PDF prohibits proprietary firmware dumping on p. 2 but requests a private recovery backup on p. 5. Resolve that conflict with the owner and Bangladeshi counsel before any physical backup. No such backup is needed for QEMU work.
- The referenced technology/business design document was not supplied here. Record it as an external dependency; do not invent additional requirements from it.

## 3. Starting point: reuse the successful research, not its unfinished assumptions

### 3.1 What has been inspected

Primary reference:

```text
/home/rifat/projects/project_firearc/docs/boot-chain-file-map.md
```

Supporting material inspected for this plan:

```text
docs/experiments/EXP-029-authenticated-debian-root.md
configs/q35-sources.tsv
configs/q35-extra-sources.tsv
configs/q35-uefi-reduced.defconfig
artifacts/exp-029/firmware-a/on.config
artifacts/exp-029/firmware-a/firmware.patch
artifacts/exp-029/firmware-a/pins.json
artifacts/exp-029/firmware-a/sdk.json
artifacts/exp-029/boot-f/command.json
artifacts/exp-029/validation-a/summary.json
scripts/debian-uki.py
justfile
```

These are historical reports/configuration/evidence, **not a fresh execution or independent revalidation performed while writing this plan**. Do not modify the old project or read/copy its private keys as part of migration.

### 3.2 Reusable baseline and actual gaps

| Area | Existing EXP-029 evidence | New work required |
| --- | --- | --- |
| Q35 firmware | Source-built coreboot + Dasharo EDK II with Secure Boot enabled | Portable rebuild; persistent state; firmware-root qualification. |
| Boot authorization | FireArc-signed UKI; unsigned, wrong-key and modified UKIs rejected | Signed systemd-boot in the actual path; revocation and authenticated key updates. |
| Root integrity | Signed-in root hash/geometry; full preverification; read-only dm-verity | mkosi implementation, installed GPT layout, two slots and authenticated fallback. |
| Existing outcomes | Reported two independent cold boots and seven negative controls | Reboot/trial/update/recovery cycles, not just fresh cold boots. |
| TPM | Build-time TPM/measured-boot options enabled | Actual swtpm attachment, event-log validation, sealing and quotes. |
| Kernel/userspace | Pinned Debian binary packages; locked-root self-test | FireArc kernel configuration, persistent appliance, hardening and health services. |
| Data | Temporary runtime state | Per-device LUKS2, escrow, migration and failure handling. |
| Updates | None in this boot path | RAUC bundles, systemd-boot backend, transaction protocol and rollback. |
| Recovery | Rejects bad root and powers off | Signed recovery, reset, break-glass and unattended fallback. |
| Build/release | Local archives, SDK/tool hashes, package inventories | Standalone mkosi pipeline, reproducibility proof, SBOM and release custody. |

Important distinctions from the inspected evidence:

- **systemd-stub is not systemd-boot.** The old UKI boots directly from `EFI/BOOT/BOOTX64.EFI`.
- `CONFIG_VBOOT_LIB=y` is not firmware verified boot. The expanded configuration has **`CONFIG_VBOOT` disabled**.
- A measured-boot Kconfig option is not evidence of measurements: the recorded successful launch has **no TPM device attached**.
- The old firmware patch removes inherited dbx content for a scoped laboratory experiment. That is not an acceptable revocation design for the new lifecycle.
- Existing firmware uses fresh writable flash copies; the new installed-device profile must preserve its enrolled state.
- Root userspace uses systemd 257, while the old host-supplied stub is reported as systemd 262. The new pipeline must explicitly qualify and preferably align stub, boot manager, ukify, measurement tools and cryptsetup-facing systemd components.
- The old full-scan/root-ready demo powers off and has no NIC. Its roughly 29-second execution is not a forwarding-time result.

### 3.3 Initial reusable firmware dependency lock

Start with these exact inputs to avoid unnecessarily rediscovering a working coreboot/UEFI combination. Review security/provenance before promoting them beyond a compatibility baseline.

| Component | Repository | Commit |
| --- | --- | --- |
| coreboot | `https://github.com/Dasharo/coreboot.git` | `b8e6b3ebfe33d08b33ac9a2ff4b9ff52ecaaa59b` |
| EDK II | `https://github.com/Dasharo/edk2.git` | `e8cd1856408429740b665e72904a07f76d795c70` |
| vboot library | `https://review.coreboot.org/vboot.git` | `f1f70f46dc5482bb7c654e53ed58d4001e386df2` |
| Brotli | `https://github.com/google/brotli.git` | `f4153a09f87cbb9c826d8fc12c74642bb2d879ea` |
| mbedTLS | `https://github.com/ARMmbed/mbedtls.git` | `8c89224991adff88d53cd380f42a2baa36f91454` |
| Screenshot driver | `https://github.com/LongSoft/CrScreenshotDxe.git` | `cf2fc003bf08a4badc3efe3540c109fa88fb0008` |
| MIPI Sys-T | `https://github.com/MIPI-Alliance/public-mipi-sys-t.git` | `370b5944c046bab043dd8b133727b2135af7747a` |
| OpenSSL | `https://github.com/openssl/openssl` | `98acb6b02839c609ef5b837794e08d906d965335` |
| libspdm | `https://github.com/DMTF/libspdm.git` | `98ef964e1e9a0c39c7efb67143d3a13a819432e0` |

Additional inherited anchors:

- Firmware SDK: `coreboot/coreboot-sdk@sha256:181452b3bc89ebc0eedcfc766d116224f0611ea4b5027857c6cfe530f5741a6c`.
- Existing QEMU machine: `pc-q35-11.1,smm=on`, TCG, `qemu64`, two vCPUs and 1536 MiB RAM. Preserve this as the initial reproduction profile, not the permanent appliance sizing.
- Existing Debian/security snapshot: `20261018T000000Z`; Debian 13/trixie, 6.12-series kernel and systemd 257 in the root package closure.
- Exact inherited package versions, sizes and SHA-256 values: `artifacts/exp-029/plan-root-a/packages.json`.
- Exact inherited host binary hashes: `scripts/debian-uki.py:PINS`. They are compatibility records, not portable package acquisition instructions.

Do not recursively fetch unlisted submodules. Preserve source Git metadata where existing guards depend on commit/cleanliness checks. Source pinning does not establish publisher-signature verification or absence of vulnerabilities.

The new lock must additionally cover mkosi, RAUC, systemd-boot/stub/ukify, dracut, swtpm/libtpms, tpm2-tools/tss, cryptsetup, filesystem tools, signing tools, the builder image and all package metadata. Resolve those versions in Phase 1; do not silently track `latest`.

## 4. Architecture and invariants

### 4.1 Trust boundaries

| Boundary | Enforcement | What it does not establish |
| --- | --- | --- |
| Initial firmware | Trusted host/approved QEMU firmware fixture initially; separately qualify a protected-RO/vboot model if mutable firmware verification is claimed | Real Intel Boot Guard, real flash protection or protection from a malicious hypervisor. |
| coreboot to UEFI | Payload inside approved firmware; verified mutable firmware regions where implemented | Signing an OS UKI does not authenticate coreboot itself. |
| UEFI to boot manager | FireArc db/dbx verifies signed systemd-boot | A firmware setup password alone is not a root of trust. |
| Boot manager to UKI | UEFI image verification remains enforced on chainloaded UKIs | A signed boot manager must not be treated as authorization for arbitrary unsigned children. |
| UKI to root | Embedded trusted initramfs, command line, root hash and geometry; dm-verity | A hash file on the ESP is not an authenticated root authority. |
| Boot state to data | LUKS2 TPM enrollment with approved PCR policy | Encryption does not make writable data or configuration inherently authentic. |
| Release to updater | RAUC CMS signatures and verity-format bundles | RAUC's bundle verity is separate from root-filesystem dm-verity. |
| Device to verifier | Enrolled TPM attestation identity, fresh challenge, quote and measured-state policy | A serial log or readiness string is not attestation. |

**QEMU threat model:** trust the host, QEMU, swtpm custody, harness, approved firmware base and verifier enrollment. Test malicious disk/ESP/update content and controlled boot-state changes. A host administrator can copy TPM state, replace firmware or restore an entire old machine snapshot; this project cannot prevent that inside ordinary QEMU.

Treat privileged runtime compromise, physical TPM bus probing, DMA, cold-boot attacks and real flash attacks as separately assessed risks. Secure Boot and LUKS do not make a running appliance invulnerable.

### 4.2 Mandatory invariants

1. Never fall back to an unsigned UKI, unverified raw root or unrestricted emergency shell.
2. The authorized UKI binds the slot identity, root authority and required security settings.
3. Verify the entire protected root before normal readiness, preserving the stronger EXP-029 behavior. Measure its boot-time cost separately.
4. After preverification, runtime root reads still go through dm-verity.
5. Unlock sensitive persistent data only after the intended authenticated boot/root path has been established.
6. Update only the inactive root/hash pair; never patch an installed verity root in place.
7. Stage and validate all candidate content before making it boot-selectable.
8. A trial boot cannot mark itself good merely because PID 1 or RAUC started.
9. Keep one known-good, permitted fallback until the candidate has passed health checks.
10. Every reboot path is bounded; exhaustion selects an authenticated fallback/recovery or halts safely.
11. Normal data unlock and local rollback do not require cloud availability.
12. Production trust must not include development signing keys or a writable-data-supplied keyring.
13. No private signing key, recovery credential or shared factory disk key appears in Git, public artifacts, firmware, UKIs or logs.
14. A/B OS rollback does not automatically roll back shared data, firmware, Secure Boot variables or TPM state.
15. Old signatures do not imply freshness; downgrade prevention and emergency rollback need an explicit compatible policy.

### 4.3 Proposed disk layout

Start with a **32 GiB virtual SSD**, GPT, 1 MiB alignment. Sizes are provisional until image-size and retention measurements in Phases 3–5; freeze layout version 1 before provisioning/update qualification.

| Partition | Label | Initial size | Format | Protection/purpose |
| --- | --- | --- | --- | --- |
| 1 | `FIREARC_ESP` | 1 GiB | FAT32 ESP | Signed systemd-boot, slot UKIs, restricted recovery UKI; no secrets. |
| 2 | `FIREARC_ROOT_A` | 4 GiB | ext4 image | Unencrypted; read-only through dm-verity. |
| 3 | `FIREARC_HASH_A` | 128 MiB | Raw verity tree | Paired with A; expected digest/geometry authenticated by UKI A. |
| 4 | `FIREARC_ROOT_B` | 4 GiB | ext4 image | Same capacity and rules as A. |
| 5 | `FIREARC_HASH_B` | 128 MiB | Raw verity tree | Paired with B. |
| 6 | `FIREARC_DATA` | Remainder | LUKS2 containing ext4 | Unique per-device encryption; persistent state, configuration and logs. |

Firmware flash/NVRAM and TPM state are separate from this OS disk. Recovery initially uses a self-contained signed UKI/initramfs, not another mutable root partition.

Storage rules:

- Use stable GPT identities and validated same-disk discovery, not `/dev/sda` ordering or root-filesystem UUIDs that change when images are replaced.
- Slot-specific UKIs may use signed partition labels/layout identifiers, with the initramfs resolving them only on the intended boot disk. Reject duplicate/missing labels, unexpected geometry and ambiguous disks.
- RAUC configuration must resolve the same validated devices. Check partition UUID, parent disk and active mapping before every write.
- Do not automatically grow, repartition or reformat an already provisioned device during ordinary updates.
- Verity covers a fixed, documented data-block range. Unprotected partition slack must not contain trusted inputs or secrets.
- Keep the ESP read-only during normal userspace operation; authorize narrow write windows for installation, boot blessing and controlled maintenance. Firmware boot counting itself needs write access before Linux runs.
- A shared FAT ESP is an availability risk. File rename is not a proof of whole-filesystem power-loss atomicity. Power-cut tests are a release gate; redesign boot-storage redundancy if the active path can be lost.

### 4.4 Writable-state layout

Mount the unlocked data filesystem at `/data`; expose only required subdirectories using explicit bind mounts.

| Content | Proposed location/handling |
| --- | --- |
| Appliance configuration and signed desired state | `/data/config/`; validate schema, authority and version before applying. |
| RAUC status, staging and transaction journal | `/data/state/rauc/`, `/data/state/update/`, exposed under required `/var/lib/` paths. |
| Service/application state | Explicit per-service directories under `/data/state/`. |
| Logs/audit and telemetry buffer | `/data/log/`, `/data/telemetry/`; quotas and retention. |
| Device identity/public enrollment metadata | `/data/identity/`; private device identity keys preferably TPM-generated/non-exportable. |
| `/run`, `/tmp` and transient `/var` content | Bounded tmpfs or explicit data-backed paths where persistence is actually needed. |
| Machine identity | Generate once per device; persist deliberately, never clone a populated machine-id. |
| `/etc` and systemd units | Immutable defaults; narrowly map approved variable files, not a blanket writable `/etc` overlay. |

Do not load executable services, unit files, libraries or boot trust anchors from general writable data. `noexec,nodev,nosuid` helps where compatible, but `noexec` does not stop an interpreter from reading a script. LUKS2 alone does not provide authenticated configuration or rollback-resistant data.

### 4.5 UKIs and boot selection

Produce one root image/tree per release and **separate signed UKIs for A and B**, unless a later reviewed design changes this. Each UKI embeds:

- Pinned systemd-stub, kernel, required microcode and complete initramfs.
- OS/build identity and kernel version.
- `rauc.slot=A` or `rauc.slot=B`, plus the matching root/hash selectors.
- Expected verity root hash, salt, geometry and corruption/failure policy.
- Required lockdown and early-boot security settings.
- TPM PCR policy public key and the matching signed PCR authorization where used.

Illustrative final ESP paths:

```text
/EFI/systemd/systemd-bootx64.efi       # FireArc-signed boot manager
/EFI/BOOT/BOOTX64.EFI                 # Signed boot-manager fallback, not a direct OS UKI
/EFI/Linux/firearc-os-<release>-A.efi
/EFI/Linux/firearc-os-<release>-B+3.efi # Candidate; +3 means bounded boot attempts
/EFI/Linux/firearc-recovery.efi       # Restricted, separately authorized recovery
/loader/loader.conf
```

The exact entry IDs, sorting/default pattern and recovery priority must be tested against the pinned systemd version. Do not assume an explicitly forced default or one-shot entry will honor fallback exactly as intended. Never pin an exhausted candidate as an unconditional default.

Disable boot-menu editing and unnecessary automatic entries in the release profile. Include an embedded `.cmdline`; test that external LoadOptions cannot weaken it. Audit UKI addons, companion initrds/credentials/extensions and SMBIOS-supplied parameters; measurement alone is not authorization.

### 4.6 TPM unlock policy

Recommended initial design, subject to measurements in Phase 5:

- Directly bind to the measured **Secure Boot policy in PCR 7**.
- Authorize **PCR 11 through signed PCR policies**, using a distinct FireArc PCR-policy signing key.
- Specify the SHA-256 bank and explicit PCR selections; do not rely on evolving tool defaults.
- Include the authorized A and B UKIs, retained fallback release and intended unlock phase.
- Do not bind normal unlock to exact PCR 0/2/4 values without an update-transition design: firmware and boot-manager updates change them.
- Do not claim PCR 7 alone identifies the intended kernel/root: it principally describes Secure Boot policy.
- A signed PCR policy authorizes all states for which a valid signature remains usable; it does not automatically revoke old OS releases.

Use a systemd-based initramfs, initially **dracut with systemd**, to make cryptsetup and PCR phase ordering explicit. Port the old full-root verification logic rather than transplanting its initramfs-tools scripts unchanged. Freeze the final generator and component versions in Phase 3.

Unlock phase, expected PCR values and signature generation must match. A policy for an initrd phase is not automatically valid after switching root or extending later PCR phase events.

### 4.7 RAUC/systemd-boot integration decision

The documented native RAUC `bootloader=efi` backend manages direct EFI boot entries, **not the required systemd-boot slot policy**. Use:

```ini
[system]
bootloader=custom
activate-installed=false

[handlers]
bootloader-custom-backend=/usr/lib/firearc/rauc-systemd-boot
```

This is an architectural fragment, not a complete deployable `system.conf`.

Design the adapter to implement RAUC's documented operations:

```text
get-primary
set-primary <A|B>
get-state <A|B>
set-state <A|B> <good|bad>
get-current                         # if needed in addition to signed rauc.slot=
```

Use rootfs A/B as bootable RAUC parents and verity A/B as their raw-image children. Keep status off the immutable root. **Do not configure the shared ESP as two ordinary raw RAUC slots**: writing a FAT image over it could erase the running/fallback boot files.

A reviewed slot hook stages the already-signed UKI and metadata without making them selectable. A separate finalize step, after successful RAUC installation, validates the complete candidate and calls RAUC's activation operation. The backend then publishes the counted entry. `activate-installed=false` intentionally creates this explicit two-stage boundary.

RAUC exposes a binary `good`/`bad` backend state while systemd-boot also has an indeterminate trial state. Document and test that translation, including a currently running final attempt whose filename already has zero attempts left. Backend boot eligibility must not be confused with completed appliance health acceptance. `set-primary` arms a trial; it must not bless the candidate as healthy.

Do not put a critical activation check solely in RAUC's system post-install handler: a failure there does not undo an already completed update. Confirm hook/backend ordering with the pinned RAUC source and integration tests.

## 5. Execution phases

Check only steps supported by recorded work/evidence. Existing research results remain historical evidence until reproduced or explicitly accepted with their original limitations. A checked documentation step does not close its independent review gate.

### Phase 0 — Freeze requirements, preserve the baseline and record decisions

**Owner:** platform lead + firmware engineer + security reviewer.  
**Depends on:** supplied PDF and existing research.  
**Output:** requirements baseline, reusable-input inventory and approved threat model.

1. [x] Record the PDF hash, date, requirement IDs and B/C scope in `docs/requirements.md`.
2. [x] Record the user's mkosi, data-only encryption and escrow decisions as ADRs.
3. [x] Inventory the old research's source/configuration/public artifact references without changing them.
4. [x] Identify dependencies hidden by `.gitignore`: sources, downloaded packages, archives, SDK images and patched build copies are not included in a Git clone.
5. [x] Verify selected archive manifests before using any artifact. Preserve failures as failures; never bypass a pin check to make migration succeed.
6. [x] Review the old lab firmware patch, expanded config and public trust fingerprints. Separate accepted fixes from deliberately omitted revocation and development-only features.
7. [x] Establish the QEMU threat model and the separate physical-root requirement. Record known untested paths and the limits of historical results.
8. [x] Create a decision/risk register with named role owners, severity, blocking gate and evidence needed to close each issue.
9. [ ] Obtain the missing technology/business design document when available; assess changes through review rather than silently changing this scope.
10. [ ] Confirm legal/clean-room rules and preserve the build team's separation from Firewalla source study. Do not perform physical vendor-image acquisition now.

**Exit gate G0:** requirements, threat model, reuse inventory and scope reviewed. No private-key transfer or destructive migration required.

### Phase 1 — Standalone workspace, pinned builders and persistent Q35 harness

**Owner:** build/release engineer + platform engineer.  
**Depends on:** G0.  
**Output:** a portable dependency lock and isolated laboratory runner.

1. [ ] Establish the planned repository structure from Section 9. Initialize signed-commit/review policy when repository setup is authorized. Git commit signing is temporarily deferred by the owner under ADR 0004; revisit it before G11, without blocking current implementation.
2. [x] Add ignore and secret-scanning rules before key generation. Separate source, immutable artifacts and per-device state.
3. [ ] Reuse the firmware source pins and SDK digest from Section 3. Verify available signed tags/releases; record unsigned upstream inputs explicitly.
4. [ ] Recreate the firmware builder from its immutable digest and archive enough metadata to reproduce it elsewhere. Do not depend only on local Docker image IDs.
5. [ ] Resolve exact Debian stable snapshot and package closures for host tools, image builder and target. Preserve signed InRelease/Release, package indexes and SHA-256 checks.
6. [ ] Treat snapshot `Valid-Until` as an explicit historical-snapshot policy. Never use `trusted=yes`, unauthenticated packages or disabled hash validation.
7. [ ] Pin mkosi, RAUC, dracut, systemd tools, swtpm/libtpms and security libraries. Review known vulnerabilities and license obligations before adopting the inherited snapshot as a new release baseline. Development tools closure and signed snapshot are implemented in `locks/debian-build.json`; portable host/appliance closure and review remain open (see `docs/builder.md`).
8. [ ] Package builds in dedicated runners/containers. Record required capabilities and mounts; do not grant broad host-disk access or a privileged Docker retry just because a build fails.
9. [ ] Reproduce EXP-029's good boot and negative controls with matching artifacts, under its original fresh-state profile. If unavailable, record which evidence cannot be reproduced.
10. [ ] Create a separate **installed-device profile** with persistent OS disk, writable firmware variable store, swtpm state and any required CMOS state across normal reboots.
11. [x] Attach one swtpm TPM 2.0 instance per device, initially using the TIS interface compatible with the inherited firmware. Qualify CRB separately if needed; do not assume interchangeability. Attachment/cold-boot smoke evidence is in EXP-001; duplicate ACPI probe issue R18 remains open before TPM policy qualification.
12. [x] Use persistent flash configured for the actual coreboot/Dasharo layout. Do not assume OVMF's CODE/VARS split applies to this monolithic firmware image.
13. [x] Add headless serial evidence and a local-only QMP control socket for automated runs; keep interactive support sessions uncaptured when they could contain recovery secrets.
14. [ ] Provide explicit new-device, stop, reboot, power-cut and isolated-snapshot operations. Ordinary boot must never silently reset TPM/NVRAM or re-enroll keys after failure.
15. [x] Start without external networking. Later add isolated WAN/LAN virtual networks, an update server and a verifier; never attach test traffic to the office network by default.
16. [ ] Keep TCG as the inherited correctness baseline; qualify KVM as a distinct profile and record different CPU/measurement/performance characteristics.

**Exit gate G1:** clean-host preflight succeeds; baseline behavior is accounted for; a provisioned VM can reboot and cold-start with the same flash/TPM identity. State restoration requires an explicit test action.

### Phase 2 — Rebuild firmware and establish FireArc trust ownership

**Owner:** firmware engineer + security reviewer.  
**Depends on:** G1.  
**Output:** self-built enforcement-on firmware, documented firmware-root model and key procedures.

1. [ ] Build coreboot and the Dasharo EDK II payload from the inherited pins and reviewed patch in a fresh offline workspace.
2. [ ] Archive expanded Kconfig, payload DSC/FDF, patches, CBFS/FMAP map, compiler hashes, build commands and complete dependency manifest.
3. [ ] Inspect firmware layout and identify code, SMMSTORE, boot-selection state and preserved regions. Verify writes land only where intended in the baseline tests.
4. [ ] Separate the initial trusted-firmware laboratory profile from any firmware-verification profile. A detached signature checked by the launcher authenticates cold-start input; it is not guest-enforced verification on every reset.
5. [ ] Investigate the pinned Q35 coreboot vboot support for an emulator model of protected RO verification of mutable firmware/payload regions. Check FMAP capacity, SMMSTORE placement, TPM usage, recovery payload and boot-state compatibility before adopting it.
6. [ ] If that model is used, sign the firmware's actual verified regions using the correct vboot tooling; test modified/wrong-key payload rejection before payload execution. Merely signing a ROM file with a PE/UKI signing tool is not firmware verified boot.
7. [ ] State exactly how the initial RO verifier is trusted/protected in QEMU. If host enforcement is the only anchor, retain that limitation and do not claim real hardware protection or resistance to a malicious host.
8. [ ] Define separate development and production trust domains. The EXP-029 30-day RSA-2048 credentials remain historical laboratory trust; do not silently adopt them as production credentials.
9. [ ] Define distinct key roles: firmware authorization, UEFI PK, KEK, EFI-image signing/db, RAUC bundle signing, PCR-policy signing, recovery authorization and device CA/attestation identity.
10. [ ] Design the PDF's offline-root/HSM/two-person ceremony. Software tokens may rehearse interfaces but cannot satisfy a claim of hardware-backed production custody.
11. [ ] Generate a new approved development hierarchy outside source/build trees; expose only public certificates to firmware builds and only the required private key to an isolated signing step.
12. [ ] Enroll FireArc PK/KEK/db and an explicit dbx policy. Remove unrelated authorization roots only after recovery and rollback implications have been reviewed.
13. [ ] Prove `SecureBoot=1`, `SetupMode=0` and exact trust fingerprints after reboot and cold start. Test that unsigned variable updates and unauthorized key replacement are refused.
14. [ ] Qualify authenticated PK/KEK/db/dbx updates, replay rejection and reset-to-default behavior. Ensure a firmware reset cannot silently restore broad vendor trust as the accepted appliance state.
15. [ ] Disable EFI shell, network boot, unnecessary option ROMs and ordinary external boot in the release profile; retain a separately controlled recovery route.
16. [ ] Confirm that source-level SMM/variable-store protection is actually suitable. Presence of `SMMSTORE` alone does not prove authenticated-variable isolation or flash write protection.

**Exit gate G2:** reproducibly buildable coreboot/UEFI enforces FireArc trust across persistent reboots; unauthorized EFI images/variable updates fail. Firmware-verification claims have a separate test result or remain **blocked**, not implied by the OS gate.

### Phase 3 — mkosi Debian image, FireArc kernel and authenticated read-only root

**Owner:** two platform engineers; security review of initramfs.  
**Depends on:** G1; coordinate trust inputs with Phase 2.  
**Output:** immutable root image, verity tree and deterministic unsigned UKI inputs.

1. [ ] Create a minimal Debian amd64 mkosi recipe using the approved snapshot and exact package lock; avoid recommends unless required and documented. A nonbootable, unsigned development probe exists at `image/smoke/mkosi.conf`; it does not satisfy the appliance requirement.
2. [ ] Build from verified package caches with networking disabled after acquisition. Record installed versions and package/source relationships.
3. [ ] Use the maintained Debian kernel as a temporary bring-up baseline, then build/qualify the FireArc configuration required by C-02. Archive source, configuration and patches.
4. [ ] Keep only necessary virtual/physical storage, console, TPM, crypto, network and filesystem support. Document required modules and future G4/G6 drivers instead of trimming them blindly.
5. [ ] Include EFI stub, dm-verity, dm-crypt, LUKS crypto support, TPM2, loop, SquashFS and RAUC dependencies. Add NBD only if streaming is later enabled.
6. [ ] Require signed/approved modules and enforce the intended kernel lockdown policy. Test unsigned module and kexec/debug interfaces; do not rely solely on a boot-time status string.
7. [ ] Select and pin systemd-based dracut initramfs generation. Include every early-boot tool/module needed for root verification, PCR policy, TPM2 unlock and controlled failure.
8. [ ] Port the old full-root verification behavior: expected hash, salt and geometry must originate inside signed UKI content, not a mutable verity superblock or ESP metadata file.
9. [ ] Generate the final ext4 root offline, with deterministic timestamps, UUID policy, ordering and image size. No machine identity, generated password, host SSH key or runtime entropy file belongs in the generic image.
10. [ ] Generate a separate SHA-256 verity tree over the documented full protected range. Use a reproducible public salt policy and archive all geometry and digest inputs.
11. [ ] Build slot-specific UKI inputs only after the final root bytes are frozen. Never modify root content after computing verity or add files in a post-install writable mount.
12. [ ] Before root mounting, perform full verification, then open the read-only verity mapping. Test both preverification and runtime corruption paths.
13. [ ] Replace the old poweroff-only rejection path with a bounded authenticated fallback interface, initially in an isolated test profile; no raw-root retry or unrestricted initrd shell.
14. [ ] Audit generic initramfs errors: absent authority, missing disk, malformed tree, missing tool/module, mount failure and timeout must not open an unauthenticated escape route.
15. [ ] Configure immutable `/usr` and controlled `/etc`; explicit writable state and tmpfs mounts follow Section 4.4. Disable ordinary on-device package mutation of the root.
16. [ ] Produce preliminary package inventory, source references and CycloneDX SBOM. Add reproducibility tests immediately rather than waiting for the final release phase.

**Exit gate G3:** mkosi builds a bootable immutable Debian root; executable, unused-protected-block and hash-tree corruption are rejected, including a coherent substituted root/tree pair with the wrong authenticated digest. No secrets or writable code overlay appear in the image.

### Phase 4 — Installed GPT disk, signed systemd-boot and A/B boot assessment

**Owner:** platform engineer + firmware engineer.  
**Depends on:** G2–G3.  
**Output:** installed A/B boot path, before RAUC integration.

1. [ ] Implement deterministic image assembly for the proposed GPT layout. Freeze labels, sizes, partition types, alignment and layout version after capacity checks.
2. [ ] Provision test root/hash pairs for both slots. Resolve devices through validated same-disk identities and reject ambiguous enumeration.
3. [ ] Align/qualify systemd-boot, systemd-stub, ukify, measurement tools and target cryptsetup-related systemd versions. Replace inherited host-path dependency with pinned builder inputs.
4. [ ] Build UKIs with ukify and inspect every embedded section. Include signed root authority and `rauc.slot=` for the actual slot.
   - Final pipeline, once Phase 5 adds PCR authorization: freeze root -> generate verity -> finalize kernel/initramfs/command-line/public-policy inputs -> calculate/sign the intended PCR states -> embed PCR signatures -> apply the final PE signature. Use ukify's supported measurement rules to avoid circular signing; never alter covered sections afterward. Rebuild all dependent signatures if any input changes.
5. [ ] Sign the boot manager and both UKIs with approved EFI-image signing credentials; verify signatures before image assembly.
6. [ ] Put **signed systemd-boot** at both the normal firmware entry and fallback `BOOTX64.EFI` path. Remove the direct-UKI bypass from the normal installed-device profile.
7. [ ] Prove the observed path is coreboot -> EDK II -> systemd-boot -> selected UKI -> verified root. Record boot-manager/stub/slot identities; a successful direct UKI launch does not pass this gate.
8. [ ] Lock down menu editing, unexpected automatic entries and external inputs. Test attempts to override root, init, verity enforcement, lockdown and emergency targets through LoadOptions/addons/companion resources.
9. [ ] Add counted candidate filenames using systemd's documented boot assessment. Start with three attempts, then tune against the measured recovery budget.
10. [ ] Establish a default-selection policy that skips exhausted candidates and retains the approved good slot. Test exact pinned-version behavior instead of assuming `bootctl set-default` is safe in all states.
11. [ ] Route boot blessing through the future FireArc health gate. Prevent the generic bless service from accepting a candidate before that gate succeeds.
12. [ ] Test A boot, B boot, persistent reboot, exhausted B, missing B UKI, wrong B root/hash pair and alternate-boot-manager paths.
13. [ ] Test unsigned/wrong-key/modified **boot managers** as well as UKIs. A valid boot-manager signature must not permit an unsigned UKI.
14. [ ] Keep firmware/boot-manager updates separate from normal root-slot replacement until their own recovery protocol exists.

**Exit gate G4:** actual systemd-boot chain is enforced; candidate attempts persist; failed candidates cannot bypass verity or permanently prevent a valid fallback.

### Phase 5 — TPM measurements and LUKS2 persistent data

**Owner:** platform engineer + TPM/security engineer.  
**Depends on:** G4 and persistent swtpm harness.  
**Output:** unattended, update-compatible data unlock with escrow recovery.

1. [ ] Confirm TPM 2.0 discovery in firmware and Linux, active SHA-256 PCR bank, resource-manager device and correct TPM initialization on cold/warm boot.
2. [ ] Collect coreboot and EDK II event logs plus PCR 0–7, 11 and relevant 12/13 measurements. Detect log handoff gaps, duplicate TPM initialization and unmeasured stages.
3. [ ] Map each measurement to its actual producer. coreboot's firmware PCR usage may differ from generic PC-client expectations; derive policy from observed, explainable logs.
4. [ ] Compare repeated unchanged boots at identical phases. Change firmware, Secure Boot state, keys, boot manager and UKI one at a time; record expected/observed PCR changes.
5. [ ] Generate per-release signed PCR 11 authorizations for both slot UKIs and the exact data-unlock phase. Keep the PCR-policy signer separate from the db signer.
6. [ ] Create per-device LUKS2 volumes only during explicit provisioning. Generate unique random volume material and a separate high-entropy recovery credential; never copy a populated shared LUKS header into the factory image.
7. [ ] Escrow the recovery credential over an approved secret-handling path with device identity and two-person access controls. Do not put it in serial capture, CLI arguments, general CI logs or the release artifact store.
8. [ ] Enroll TPM2 using `systemd-cryptenroll` with explicit PCR 7 binding and the approved signed PCR 11 policy. Validate the policy against the current boot before removing any temporary provisioning credential.
9. [ ] Use the corresponding pinned `systemd-cryptsetup` implementation and crypttab configuration. Verify that both retained and candidate systemd versions can unlock the same enrolled token format.
10. [ ] Unlock only after root integrity checks and at the selected PCR phase. Mount `/data` and required bind mounts before dependent services; missing data must not cause secrets to be written to an unencrypted fallback directory.
11. [ ] Test normal A boot, B boot, healthy OS update and fallback without manual re-enrollment. Routine OS updates must not require an escrow key or network key service.
12. [ ] Move the OS disk to a fresh VM with a different swtpm identity: unattended unlock must fail. Copying the entire old TPM state is outside this test's physical-identity claim.
13. [ ] Test Secure Boot disabled, unauthorized UKI, missing PCR signature, wrong signing key, wrong phase, TPM clear/replacement and unavailable TPM. Refuse sensitive unlock; do not auto-format or silently enroll the new TPM.
14. [ ] Rehearse authorized offline escrow recovery on an isolated clone, then rotate credentials and update the escrow record after recovery. Protect LUKS header backups as sensitive recovery material.
15. [ ] Document header-backup retention: an old header may restore an old keyslot. Keyslot removal alone is not a guarantee that an old offline backup cannot unlock unchanged ciphertext.
16. [ ] Establish data quotas, journal behavior, mount restrictions, log retention and compatibility with the future 72-hour telemetry-buffer requirement; record sizing as an H interface, not an implemented agent feature.

**Exit gate G5:** unique TPM-bound data unlock works across permitted A/B transitions; a moved disk does not unlock with another TPM; authorized escrow recovery is tested; failed unlock never becomes silent reset or plaintext persistence.

### Phase 6 — Signed RAUC bundles, custom boot backend and two-stage activation

**Owner:** platform/update engineer + security reviewer.  
**Depends on:** G4–G5.  
**Output:** an authenticated, inactive-slot-only update transaction.

1. [ ] Pin matching host/target RAUC versions and document compiled features. Start with locally downloaded **verity-format** bundles; defer streaming/adaptive updates until full-image correctness is qualified.
2. [ ] Create a dedicated RAUC signing PKI/keyring, separate from UEFI and TLS trust. Qualify intended certificate purpose, validity/CRL behavior and trusted-time bootstrap using the pinned OpenSSL/RAUC versions.
3. [ ] Install RAUC configuration and trust anchors in immutable root. Limit D-Bus installation/marking operations to the update service; ordinary service users must not initiate arbitrary installs.
4. [ ] Describe rootfs A/B as raw-image bootable slots and verity A/B as children of the corresponding parent. Use shared encrypted-data status, not per-slot writes into a verity root.
5. [ ] Implement the custom backend operations from Section 4.7. Validate arguments, output only documented machine-readable values, serialize access and propagate every error.
6. [ ] Cross-check signed `rauc.slot=`, actual mapped root, selected UKI and GPT identities. Refuse writes if the active slot cannot be established unambiguously.
7. [ ] Define bundle contents: root image, tree image, signed A/B UKIs as required, signed-in release identity, compatibility/layout/security-epoch information and reviewed hook executable.
8. [ ] Retain built-in compatibility checks where possible. If an install-check hook replaces them, explicitly reproduce compatibility, version and layout checks; do not accidentally turn the hook into an unconditional allow.
9. [ ] Define idempotent slot hooks for staging UKIs and transaction metadata. Stage outside systemd-boot's discoverable paths, with no `.efi` candidate accidentally visible early.
10. [ ] Configure `activate-installed=false`; let RAUC mark the target unavailable and write the inactive root/tree group without making it primary.
11. [ ] After successful RAUC completion, finalize under an exclusive update lock: verify target image readback, full root/tree validation, UKI signature, signed root authority, slot identity, required trust and retained fallback availability.
12. [ ] Make activation the last step: flush data/block writes, persist a transaction journal, stage the final ESP file on the same filesystem, flush it, publish the counted entry and flush filesystem metadata before switching preference.
13. [ ] Implement `set-primary` so it activates only a completely validated candidate or explicitly permitted existing slot. Revalidate stage content rather than trusting a stale `success=true` file.
14. [ ] Test interrupted/duplicated finalize calls and a crash between publication and preference update. Recovery must reconcile actual files/counters and signed content, not infer success from RAUC status alone.
15. [ ] Keep active UKI/root/hash, encrypted data, recovery image, firmware and trust database untouched by an ordinary OS update, except the narrowly required shared boot-selection metadata.
16. [ ] Reject wrong signature, wrong device/layout, oversized/truncated image, malformed manifest, active-slot target and insufficient storage before activation. Never use `--no-verify` as a passing update path.
17. [ ] Add a small laboratory update controller for stage/finalize/reboot/status. Use RAUC's supported D-Bus interface where practical; a full cloud update service is out of scope.

**Exit gate G6:** a valid bundle is installed only to the inactive pair; no candidate becomes bootable until all validations pass; malformed/unauthorized bundles cannot replace the active system or its trust anchors.

### Phase 7 — Health checks, automatic rollback and data compatibility

**Owner:** platform engineer + network/test engineer.  
**Depends on:** G6.  
**Output:** bounded unattended acceptance/fallback, not merely selectable A/B images.

1. [ ] Implement a local boot-health service with explicit dependencies before `boot-complete.target` or an equivalent single controlled blessing path.
2. [ ] Require: expected Secure Boot state, expected slot/build, read-only verified root, successful data unlock/mount, required services, valid configuration, usable RAUC state and local forwarding self-test.
3. [ ] Check the actual root mapping and selected UKI rather than trusting an editable file on data. Record identity mismatches as failure.
4. [ ] Define a short stability window and per-check timeout. Cloud reachability, live threat-feed availability or external ISP availability must not create false boot-failure loops.
5. [ ] Coordinate RAUC `mark-good` with systemd boot blessing through the custom backend. Use one authoritative transition and idempotent reconciliation; do not run two independent services that disagree about acceptance.
6. [ ] On failure, mark the candidate bad when possible and request reboot; on early userspace/initrd failure, rely on persistent boot counting plus a qualified reset/watchdog path.
7. [ ] Handle firmware signature denial or missing UKI before Linux starts. A Linux watchdog cannot recover that stage; test systemd-boot/UEFI's actual next-entry behavior or implement a reviewed firmware-level timeout/fallback.
8. [ ] Qualify a QEMU watchdog/reset mechanism for kernel hangs; distinguish a guest watchdog result from a host test timeout that manually restarts the VM. Recheck real watchdog coverage on hardware.
9. [ ] Exercise three-attempt exhaustion and immediate-rejection paths. Measure total recovery time; reduce retries if needed, without making transient faults cause unnecessary rollback.
10. [ ] Define failure after a previously good slot later becomes corrupt: it must select the other permitted slot/recovery, not spin forever merely because its boot counter was already removed.
11. [ ] Design shared-data migrations independently of root rollback. Prefer backward-compatible additive migrations or transactional per-release config/state generations with retained prior versions.
12. [ ] Keep device identity, encryption material and append-only/audit state outside disposable candidate configuration generations. Do not blindly restore all `/data` when reverting a root slot.
13. [ ] Do not commit an irreversible schema change or delete prior data during the trial window. Test old OS reading state after a failed new-OS migration.
14. [ ] Cover full data filesystem, log/audit pressure, read-only data mount, interrupted migration, failed policy application and concurrent update attempts.
15. [ ] Retain an audit record explaining candidate version, attempts, health failure, selected fallback and final accepted version without exposing keys.

**Exit gate G7:** a deliberately broken but correctly signed update rolls back automatically without a site visit; data remains usable; boot-manager/initrd/kernel/userspace failure coverage is explicit. Host-assisted reboot alone does not count as unattended rollback.

### Phase 8 — Measured boot and independent TPM quote verification

**Owner:** TPM/security engineer; backend engineer for the test verifier.  
**Depends on:** G5 and stable A/B measurement identities.  
**Output:** the PDF's working test attestation server and evidence.

1. [ ] Define an enrollment record binding device identity, TPM endorsement/attestation identity, allowed firmware family, trust epoch and permitted release measurements.
2. [ ] Generate the attestation key in the TPM and enroll its public identity over a controlled provisioning channel. Where EK binding is claimed, demonstrate credential activation or the selected equivalent proof.
3. [ ] Treat swtpm-generated credentials as laboratory trust. Do not present them as manufacturer-certified discrete-TPM identity or physical non-exportability.
4. [ ] Run the verifier outside the guest on an isolated laboratory endpoint. It generates a fresh random challenge with expiration and single-use tracking.
5. [ ] Collect a quote covering selected firmware/Secure Boot PCRs and the UKI/phase PCRs, plus the event logs and build/slot metadata.
6. [ ] Validate AK trust, quote signature, nonce, PCR selection/bank, quoted digest, device binding and freshness. Replay the event log into the quoted PCR values.
7. [ ] Compare the replayed state with an independently approved measurement/release policy. A self-consistent but malicious event log is not itself an allowlist.
8. [ ] Test good A, good B, retained rollback, approved firmware transition, changed keys and recovery boot at defined phases.
9. [ ] Reject stale/reused nonce, another device's AK, altered log, wrong bank/selection, missing measurements, unknown firmware and unapproved UKI state.
10. [ ] Record local boot integrity and remote attestation status separately. An offline verifier does not automatically invalidate a locally known-good boot or repeatedly trigger OS rollback.
11. [ ] Define the future arcd interface: provisioning creates a TPM-held device identity and exposes enrollment/measurement status. Full transport/telemetry/response implementation remains Workstream H.

**Exit gate G8:** an independent verifier accepts fresh quotes for approved releases and rejects identity, freshness and measured-state substitutions. A readiness marker is never accepted as quote evidence.

### Phase 9 — Signed recovery, factory reset and one-time break-glass

**Owner:** platform engineer + security reviewer.  
**Depends on:** G5–G8.  
**Output:** recoverability without weakening normal boot or encrypted-data policy.

1. [ ] Build a minimal self-contained recovery UKI with pinned tools and no uncontrolled root shell or automatic sensitive-data unlock.
2. [ ] Sign recovery under the reviewed recovery policy. Recovery is still subject to Secure Boot and revocation; preserve its identity in attestation policy.
3. [ ] Provide serial-only restricted diagnostics by default. Forwarding is disabled in recovery unless a separately approved safe-mode policy explicitly allows it.
4. [ ] Implement controlled entry after both slots are unusable or by authorized local action. Test what the pinned boot manager actually does when all ordinary entries are exhausted or invalid.
5. [ ] Separate three operations: non-destructive diagnostics/slot repair, destructive factory reset, and authorized encrypted-data recovery using escrow.
6. [ ] Require physical/local intent plus a device-bound authorization for destructive operations. Normal unlock failure is not permission to erase data.
7. [ ] Prototype the PDF's TPM-bound one-time break-glass code: device-bound challenge, approved signer, explicit operation, expiry where trustworthy time exists, rate limit and TPM-backed consumed-token/counter state.
8. [ ] Reject reuse across reboots and across devices. A token consumed only in rollbackable `/data` is not sufficient for a one-time guarantee. QEMU host snapshot replay remains outside the physical-security claim.
9. [ ] Do not let a break-glass token bypass Secure Boot, verity or RAUC signature validation. Data-unlock escrow is a separate approval, not an automatic side effect of diagnostics.
10. [ ] Restore root slots only from authenticated images/bundles with valid layout and security policy; preserve retained trust state unless a separate provisioning workflow authorizes replacement.
11. [ ] Factory reset must revoke/recreate per-device data encryption as specified, remove tenant state and define whether enrollment identity is retained or reissued.
12. [ ] Address escrow and header backups in reset policy. Destroying a local keyslot does not erase plaintext copies, escrow records or previously exported ciphertext/header combinations.
13. [ ] Test lost TPM, damaged LUKS header, two bad roots, absent ESP entry, bad recovery signature, full disk and power interruption during repair/reset.
14. [ ] Provide authenticated recovery/installer media if the ESP itself is unusable. Ordinary external boot remains disabled; document the controlled exception and signed boot components rather than saying an ISO file alone is 'UEFI-signed'.

**Exit gate G9:** authorized diagnostics, reset, repair and escrow recovery work; unauthorized users cannot turn recovery into a boot-verification bypass; one-time/device-bound behavior is tested.

### Phase 10 — Signed firmware updates, trust rotation and downgrade policy

**Owner:** firmware engineer + release/security engineers.  
**Depends on:** G2, G7–G9.  
**Output:** separately qualified firmware/key lifecycle and an explicit rollback window.

1. [ ] Define firmware release identity, board compatibility, signed region hashes, minimum supported version and preserved flash regions.
2. [ ] Select a delivery mechanism actually supported by the pinned coreboot/EDK II combination: authenticated capsule or a reviewed FireArc-signed flashing workflow. The inherited configuration has capsule updates disabled; do not assume fwupd integration already exists.
3. [ ] For a QEMU host-side update prototype, verify the signed firmware artifact before applying it and explicitly label the host-trusted boundary. This alone is not guest-enforced flash authentication.
4. [ ] If using vboot/protected firmware regions, update and verify the intended mutable region while preserving the root verifier, SMMSTORE, provisioning identity and rollback state.
5. [ ] Ensure mutable firmware verification covers the actual UEFI payload and relevant coreboot stages/configuration. A payload hash printed by the OS is not equivalent to rejection before execution.
6. [ ] Stage approved measurement/PCR-policy transitions before changing firmware or Secure Boot keys. PCR 7 changes can invalidate data enrollment even if the OS is unchanged.
7. [ ] Rehearse bridge enrollment/authorization for the next Secure Boot policy with the pinned tools; retain current and next recovery paths until both A and B are validated. Do not wipe the only usable TPM enrollment first.
8. [ ] Test corrupted, unsigned, wrong-board, old and interrupted firmware updates. Never overwrite a complete monolithic flash image without an explicit policy for device-specific variable regions.
9. [ ] Demonstrate known-good firmware recovery in QEMU. A host restoring an archived flash file is an emulator recovery simulation, not proof of automatic physical unbricking.
10. [ ] Separate ordinary release version from **security epoch**. Keep candidate and fallback bootable within the permitted epoch; do not advance an irreversible minimum merely because installation completed.
11. [ ] Enforce installation downgrade policy in the trusted update controller/RAUC integration. Record that an install-time version check alone cannot stop offline replay of an already-signed old UKI.
12. [ ] Demonstrate authenticated dbx/hash or signer revocation for explicitly forbidden boot artifacts, including direct-launch and fallback paths. Confirm rejection still holds with old ESP/root content.
13. [ ] Keep permitted fallback and recovery artifacts valid before committing revocation. Test crashes between key/dbx update, TPM policy transition and boot blessing.
14. [ ] If a general hardware-backed minimum security epoch is required, design its protected firmware/TPM-NV enforcement separately. Stock systemd-boot plus a mutable version file does not provide it; old code that omits a new check is a bypass risk.
15. [ ] Test authenticated-variable replay and reset-to-factory behavior. Document which downgrade resistance survives disk replacement, NVRAM reset, TPM clear and physical reflash; do not claim more than the platform enforces.
16. [ ] Run two-person release and key-rotation rehearsals, including signer compromise, expired RAUC certificate, revocation distribution, HSM loss and escrow access audit.

**Exit gate G10:** signed firmware delivery and recovery are demonstrated at the stated trust boundary; key rotation preserves boot/data access; forbidden artifacts are rejected; remaining hardware-root and generalized anti-rollback limitations have explicit owners.

### Phase 11 — Hardening, reproducibility, SBOM and release CI

**Owner:** build/release engineer + platform/security engineers.  
**Depends on:** begin during Phase 3; complete after G10.  
**Output:** repeatable, reviewable release artifacts and security baseline.

1. [ ] Build identical source/configuration/package inputs twice on independent clean runners; do not reuse the first runner's build output/cache as the second result.
2. [ ] Compare root image, verity tree, unsigned A/B UKIs, firmware executable regions and the unprovisioned factory image byte-for-byte. Use diffoscope or equivalent diagnostics on mismatches.
3. [ ] Normalize filesystem metadata, archive ordering, timestamps, build paths, build IDs and public salt/UUID policies. Document each reproducibility control.
4. [ ] Keep provisioning randomness separate: populated LUKS headers, TPM state, machine identities, keys and live NVRAM are intentionally device-specific, not reproducible release payloads.
5. [ ] Define signing-envelope treatment explicitly. Time-bearing CMS/signature metadata may differ; this is not permission for root/firmware payload differences. Independently verify payload reproducibility and publish the exact final signed release hashes.
6. [ ] Publish both reproducibility attestations and their precise artifact coverage. Do not call a rebuilt Debian image a source rebuild of every Debian package.
7. [ ] Generate CycloneDX SBOMs covering OS packages, kernel, firmware, payload, bundled libraries, custom code and recovery image. Link them to final artifact hashes and source revisions.
8. [ ] Perform license/vulnerability scans; publish required corresponding source, patches/build scripts and legally reviewed GPL source-offer material. Review firmware blobs/redistribution rights separately.
9. [ ] Implement AppArmor profiles per shipped service; enable auditd and the intended parser seccomp filters. Test enforcement and denied operations rather than merely installed packages.
10. [ ] Give service users no login shell; remove default credentials, passwordless recovery, unused packages, listeners and debug interfaces. Keep WAN inbound support disabled.
11. [ ] Apply appropriate systemd sandboxing, capabilities and filesystem restrictions per service. RAUC/cryptsetup need narrowly reviewed privileges; do not copy a generic sandbox that disables their required safety checks.
12. [ ] Verify unsigned-module rejection, kernel lockdown, protected trust/configuration paths, immutable units, mount restrictions and no raw-disk access for unprivileged services.
13. [ ] Record a CIS Debian benchmark assessment per build, with justified appliance exceptions; do not invent a passing score or apply desktop/server controls blindly.
14. [ ] Separate CI acquisition, build, verification, signing and publication identities. Pull requests must never access production signing keys, HSM sessions or device escrow.
15. [ ] Require signed commits/tags or equivalent reviewed provenance, two-person release approval and immutable artifact storage. Sign hashes/provenance independently of an unauthenticated checksum file.
16. [ ] Run a snapshot-refresh/security-update rehearsal through the same mkosi -> verity -> UKI -> RAUC path. A pinned historical snapshot is not an ongoing security-maintenance policy.

**Exit gate G11:** two independent builds meet the documented identical-hash requirements; hardening assessment, SBOM, licenses/source obligations, provenance and controlled signing are present for every release.

### Phase 12 — Integrated qualification, power-loss campaign and performance targets

**Owner:** test engineer + platform/network engineers.  
**Depends on:** G7–G11.  
**Output:** reviewed QEMU acceptance evidence and hardware handoff package.

1. [ ] Provision a new VM from the unprovisioned factory image; enroll trust/TPM/data through the documented process, then disconnect provisioning media.
2. [ ] Boot the installed system through the required signed chain; verify immutable root, encrypted persistence and local health acceptance.
3. [ ] Add an original minimal declarative forwarding policy fixture on isolated LAN/WAN networks. Compile it to nftables rather than treating hand-written appliance rules as the product policy model.
4. [ ] Send traffic through a separate LAN client and upstream endpoint; record the first successfully forwarded permitted packet and an expected blocked flow.
5. [ ] Install a healthy signed RAUC update while forwarding, reboot, accept it, preserve data and verify the new TPM quote.
6. [ ] Install a correctly signed but deliberately broken update and observe unattended fallback. Repeat in both A->B and B->A directions.
7. [ ] Run every security/control test in Section 8, including firmware and boot-manager denial, root/tree substitution, encrypted-data transplant, attestation replay and recovery authorization.
8. [ ] Inject hard VM stops during target invalidation, root/tree writes, UKI staging, flush, publication, preference change, first trial boot, health blessing and data migration.
9. [ ] Reopen the same disk/flash/TPM state after each cut; do not hide failure by recreating NVRAM or swtpm. Verify a permitted known-good path and unchanged data.
10. [ ] Use explicit write-back/flush behavior and block-layer fault tests to examine unflushed writes; process termination alone is not a complete storage-power-loss model.
11. [ ] Record shared-ESP integrity after every cut. If FAT corruption can remove the active/fallback path, fail the atomic-update gate and redesign; do not waive it because RAUC installed the root successfully.
12. [ ] Run repeated normal update/rollback cycles, variable-store usage tests and a long-running encrypted-persistence soak. Choose and record cycle counts/seeds before the campaign.
13. [ ] Measure power-on to first forwarding against **60 seconds**. Break down firmware, boot manager, full verity scan, TPM unlock and service readiness.
14. [ ] Measure last successful pre-reboot forwarding to first successful post-update forwarding against **120 seconds**. Report staging/download time, healthy-update downtime and failed-update recovery separately.
15. [ ] Report TCG/KVM environment and repeated-run distributions, not only the best observation. VM timing is not G4/G6 throughput, thermal, SSD or real watchdog qualification.
16. [ ] If full-root scanning misses the time budget, optimize and remeasure first. Changing to on-demand-only verification would change the stronger inherited requirement and needs an explicit ADR/user review.
17. [ ] Publish a reproducible demo runbook, test report, final release manifest and all unresolved risks with owners. Distinguish untested, failed, simulated and passing cases.

**Exit gate G12:** QEMU lifecycle acceptance passes without signature bypasses, manual rollback or hidden state resets. Unmet targets and unavailable physical evidence remain visible, not declared complete.

### Phase 13 — Transfer to reference units and ODM hardware when available

**Owner:** firmware + hardware + platform engineers.  
**Depends on:** hardware arrival, recovery equipment and legal approval.  
**Output:** physical B/C qualification and firmware requirements for the G4/G6 specification.

1. [ ] Start with the PDF's Protectli Vault Pro VP2440 and VP6650 reference models, subject to exact support/revision verification. Preserve stock units; designate separate probe/reflash units and establish a recovery procedure before any write.
2. [ ] Confirm exact board revision, supported Dasharo/coreboot source, required blobs, TPM model/interface and storage/NIC drivers. Do not flash a Q35 ROM onto physical hardware.
3. [ ] Inventory Boot Guard mode, fused authority, flash descriptor/locks, ME/CSME state and TPM capabilities using approved public tools. Record results per physical sample.
4. [ ] Resolve the PDF's backup/legal conflict before any private vendor-image read. Never redistribute a proprietary recovery image.
5. [ ] Build board-specific firmware from source, verify FireArc key ownership and establish UART/SPI recovery with correct voltage/pinout and programmer support.
6. [ ] Implement/verify the board's real firmware root: FireArc-controlled Boot Guard where available, or a documented protected-RO verification strategy. Unfused plus writable flash is not the final security answer.
7. [ ] Verify real flash write protection, SMM/authenticated-variable protections, setup controls and ordinary USB/network-boot restrictions. Assess physical bypasses explicitly.
8. [ ] Re-provision fresh hardware TPM identities and unique LUKS data; do not migrate swtpm secrets as production identities. Recompute/approve board-specific measurement baselines.
9. [ ] Repeat UKI/boot-manager/root tamper, TPM transplant, escrow, A/B, key-rotation, firmware-update and recovery tests on every supported model.
10. [ ] Perform real power cuts/brown-outs during update and boot, plus the PDF's reliability campaign with the hardware team. VM crash survival does not replace storage/flash power-loss evidence.
11. [ ] Verify watchdog coverage from firmware handoff through kernel/userspace hangs. Confirm pre-Linux signature denial recovers without a technician where claimed.
12. [ ] Measure real forwarding boot/update downtime; coordinate thermal/power/NIC and 500-cycle reliability requirements with Workstream A. Do not claim IPS/NDR throughput from this boot-chain project.
13. [ ] Decide/test ME HAP/disable policy only where documented/supported for the exact model, with stability and recovery evidence.
14. [ ] Deliver ODM firmware requirements: FireArc root-key control, discrete TPM2, recovery header/socket strategy, console, protected flash, signed updates and key/provisioning ownership.
15. [ ] Review hardware-pending risks at the PDF's final R&D gate. Anything unmet stays a named build-plan risk with an owner.

**Exit gate G13:** actual units meet the applicable PDF firmware/OS criteria. Until then, production hardware-root and physical recovery claims remain pending.

## 6. Update and rollback state machine

Implement this state machine before optimizing download size or adding a cloud updater.

```text
GOOD(A)
  -> authenticate bundle and compatibility
  -> lock update; invalidate B's old boot entry
  -> INSTALLING(B): write B root + B tree; keep A unchanged
  -> STAGED(B): store signed UKI/metadata outside discovered boot paths
  -> validate readback, signature, verity, slot, policy and fallback
  -> TRIAL(B, attempts=3): publish counted entry and select by tested policy
  -> reboot
       -> HEALTHY(B): coordinated RAUC good + boot blessing -> GOOD(B)
       -> FAILED(B): mark bad/exhaust attempts -> GOOD(A)

No permitted ordinary slot remains
  -> authenticated restricted recovery
  -> authorized repair/reset, or safe halt
```

State ownership:

| State | Authority/storage | Required behavior |
| --- | --- | --- |
| Release authenticity | UKI PE signatures, RAUC CMS, firmware signatures | Verify before use; mutable status cannot substitute for signatures. |
| Root integrity | Expected hash inside authorized UKI | Validate selected root/tree; reject mismatched pairs. |
| Running slot | Signed UKI command line + actual mapped-root/boot identity | RAUC/backend cross-check; ambiguity stops installation. |
| Boot attempts | systemd-boot counted filenames | Persist before attempting candidate; survive restart. |
| Health acceptance | FireArc health service through coordinated backend/blessing | No unconditional mark-good service. |
| Transaction progress | Encrypted-data journal plus actual staged/ESP/device state | Idempotent recovery; journal is not cryptographic authority. |
| Shared data generations | Transactional application/configuration schema | Preserve a rollback-compatible generation. |
| Security revocation | Authenticated trust state/protected platform policy | Distinct from ordinary trial rollback. |

Crash-consistency rules:

- Before activation, a reboot must continue to use A; partial B is unavailable.
- At activation, either the old good entry remains selected or the complete authenticated candidate is selectable; never a partially written UKI.
- After activation but before acceptance, attempts remain finite even after power loss.
- A crash during blessing/status update must reconcile safely without accepting an untested candidate or deleting the only good fallback.
- Do not install another update while the current system is an unaccepted trial; it could overwrite the only known-good fallback.
- The rollback window must include compatibility of LUKS tokens, firmware, keys, recovery and data schema, not just root images.

## 7. Keys, provisioning and recovery controls

| Key/material | Purpose | Custody |
| --- | --- | --- |
| Firmware authorization root/signers | Authenticate permitted firmware/verified regions | Offline root; controlled signing service/HSM for production. |
| UEFI PK | Platform ownership and KEK administration | Offline/highly restricted; not routine CI. |
| UEFI KEK | Authenticated db/dbx maintenance | Restricted ceremony/signing workflow. |
| EFI-image signing key | systemd-boot, UKIs and approved EFI recovery components | Dedicated lab signer initially; HSM-backed production signer. |
| RAUC signing root/signers | Authorize update bundles | Dedicated PKI; no TLS or UEFI trust reuse. |
| PCR-policy signing key | Authorize measured UKI/boot phases for data unlock | Separate from EFI and RAUC signers; release-controlled. |
| Recovery authorization key | Device/operation-bound break-glass approval | Offline/restricted approval, separate from generic support access. |
| Device identity/AK | Enrollment, quotes and future device authentication | Generate inside each TPM; separate roles as appropriate. |
| LUKS volume material | Encrypt one device's data | Unique per device; never a fleet-wide factory key. |
| Recovery credential/header backups | Authorized disaster recovery | Per-device offline escrow, audited two-person retrieval and retention policy. |

Do not rely on an EFI signing certificate's expiration date as firmware-enforced revocation: qualify actual UEFI behavior and use authenticated db/dbx lifecycle controls. RAUC certificate/time validation is a separate contract.

Provisioning must be a separate, explicit workflow:

1. Authenticate the firmware/image and confirm the device is unprovisioned.
2. Establish intended Secure Boot ownership without importing private signing keys.
3. Establish TPM identity and enrollment records.
4. Create unique encrypted data and capture the recovery credential through the approved secret channel.
5. Enroll the tested TPM policy, remove temporary provisioning credentials only after validation, and record public fingerprints/status.
6. Generate device-specific machine identity and initial configuration.
7. Boot both permitted slots, verify data unlock and attest the result.
8. Remove provisioning media and close provisioning-only interfaces.

A failed provisioning marker is not permission to repeat destructive formatting. Reset/re-enrollment requires explicit authorization and must distinguish a new device from a damaged provisioned one.

## 8. Acceptance-test catalog

Each test needs setup, mutation/action, expected result, actual result, artifacts and a reviewer. Run failures against disposable copies, never the reference base artifacts.

| Test ID | Scenario | Required result |
| --- | --- | --- |
| BOOT-01 | Installed cold boot and warm reboot | Required coreboot/UEFI/systemd-boot/UKI path, Secure Boot on, correct slot, verified root. |
| BOOT-02 | Unsigned/wrong-key/modified boot manager | Firmware refuses before untrusted boot-manager execution. |
| BOOT-03 | Unsigned/wrong-key/modified UKI through signed systemd-boot | Refused before untrusted kernel/initramfs execution. |
| BOOT-04 | External cmdline/initrd/addon/SMBIOS weakening attempt | Cannot disable verity/lockdown or change authorized boot authority. |
| BOOT-05 | Unauthenticated key update, setup reset and variable replay | Unauthorized trust transition rejected or detected as unacceptable state. |
| ROOT-01 | Modify executable protected block | Candidate rejected; permitted fallback/recovery only. |
| ROOT-02 | Modify otherwise-unused protected block | Full preverification rejects before normal readiness. |
| ROOT-03 | Modify verity tree | Rejected; no raw-root fallback. |
| ROOT-04 | Replace root/tree with coherent different pair | Original UKI refuses the new digest. |
| ROOT-05 | Runtime protected-root corruption/read | dm-verity error triggers defined bounded failure, never silent acceptance. |
| ROOT-06 | Missing tool, module, authority or root device | Restricted failure/fallback; no generic unauthenticated rescue shell. |
| TPM-01 | Repeated identical boots at fixed phase | Explainable repeatable PCR/log behavior; measured stages present. |
| TPM-02 | Change firmware, keys, Secure Boot or UKI | Expected measurements change; policy follows approved state only. |
| DATA-01 | A/B/reboot/healthy update | Unattended data unlock and persistence, no normal escrow use. |
| DATA-02 | Move disk to another TPM | Unattended unlock fails; authorized escrow remains a deliberate exception. |
| DATA-03 | TPM unavailable/cleared, wrong PCR/phase/signature | No sensitive unlock, plaintext fallback or auto-format. |
| DATA-04 | Escrow and header recovery | Controlled recovery, audit and post-recovery rotation succeed. |
| DATA-05 | Full/corrupt/read-only data filesystem | No premature good marking or unsafe overwrite; documented safe state. |
| UPD-01 | Valid update A->B and B->A | Inactive pair only; data retained; health acceptance; approved quote. |
| UPD-02 | Bad signature, wrong model/layout, oversized/truncated bundle | Refused without activating incomplete content. |
| UPD-03 | Correctly signed broken candidate | Automatic bounded rollback without a site visit. |
| UPD-04 | Kernel/initrd/userspace hang | Qualified watchdog/reset plus attempt exhaustion; host timeout distinguished. |
| UPD-05 | Pre-Linux signature/load failure | Actual automatic next-entry/fallback behavior demonstrated. |
| UPD-06 | Cut power at every transaction boundary | Known-good permitted boot remains; state reconciles; data usable. |
| UPD-07 | Crash during blessing/finalize; repeated finalize | Idempotent result; no false acceptance or fallback deletion. |
| UPD-08 | Interrupted/incompatible data migration | Prior permitted OS can use retained compatible data. |
| UPD-09 | Install during trial/concurrent operations | Refused/serialized; only good fallback preserved. |
| ATT-01 | Fresh approved quote A/B/recovery | Independent verifier correctly classifies each permitted role/state. |
| ATT-02 | Replay, altered log, wrong AK/PCR bank or unknown release | Rejected; identity/freshness/policy checks all exercised. |
| ATT-03 | Verifier/network offline | Local known-good operation does not enter an endless rollback loop. |
| REC-01 | Both OS slots unusable | Restricted authenticated recovery or safe halt; no unsigned bypass. |
| REC-02 | Wrong/reused/other-device break-glass token | Rejected, including after reboot. |
| REC-03 | Authorized repair/reset; power cut during reset | Explicit operation, predictable data/identity outcome and audit. |
| FW-01 | Modified firmware/payload verified region | Rejected before execution where firmware-verification model is claimed. |
| FW-02 | Signed firmware update success/interruption | Preserved device state and demonstrated recovery at stated boundary. |
| KEY-01 | db/KEK/PCR/RAUC key rotation | Both permitted slots and recovery remain usable; new policy enforced. |
| KEY-02 | Revoked EFI artifact/offline old disk replay | Revoked artifact refused on all qualified launch paths. |
| HARD-01 | Unprivileged unit/config/keyring/raw-disk tampering | Denied; mutable data cannot replace trusted service code. |
| HARD-02 | Unsigned module/debug/breakout paths | Intended lockdown/AppArmor/seccomp behavior verified. |
| BUILD-01 | Two clean independent builds | Identical documented release-payload hashes. |
| BUILD-02 | SBOM/license/source/provenance/secret scan | Complete, linked to release, no blocking license or key leakage. |
| PERF-01 | Power-on to first forwarded packet | Target <=60 s, measured and reported, not assumed. |
| PERF-02 | Healthy-update forwarding downtime | Target <120 s; broken-update recovery reported separately. |
| HW-01 | Real fuse/flash/TPM/watchdog/power-loss matrix | Pending hardware; QEMU cannot mark it passed. |

These are minimum categories, not a claim that one run exhaustively covers all corruptions or power-loss behaviors.

## 9. Planned repository and command interface

The implementation is being created incrementally. See [progress](docs/progress.md) for existing/verified components; the tree below is the **target layout**, not a claim that every file/workflow exists:

```text
PLAN.md
justfile
locks/                       sources, packages, builders, tool versions and hashes
firmware/
  q35/                       defconfig, FMAP, reviewed EDK II/coreboot patches
  keys/                      public certificates/fingerprints only
image/
  mkosi.conf
  mkosi.conf.d/
  kernel/                    configuration, source lock and patch set
  initrd/                    dracut modules, full-verification and failure logic
  root/                      immutable configuration and service units
  repart.d/                  GPT assembly policy
update/
  rauc/                      system configuration, manifests and reviewed hooks
  backend/                   systemd-boot adapter and activation/health logic
recovery/                    restricted UKI, reset and break-glass workflows
lab/
  q35/                       reproducible VM profiles and network topology
  verifier/                  test enrollment and attestation policy
scripts/                     acquisition, build, signing, launch and evidence helpers
tests/                       unit, integration, corruption and power-loss campaigns
docs/
  requirements.md
  architecture.md
  threat-model.md
  reuse-inventory.md
  key-ceremony.md
  provisioning.md
  update-state-machine.md
  recovery.md
  hardware-handoff.md
  decisions/
  experiments/
artifacts/<build-id>/         immutable outputs/manifests; external store in CI
run/<device-or-test-id>/      disks, flash, TPM state, sockets and private test state
```

Use a thin `justfile`, consistent with the research project. Keep complex orchestration in tested scripts; reuse Python helpers where suitable and upstream build systems for upstream components. Small security-sensitive custom services/adapters can follow the research project's Rust direction without rewriting RAUC/systemd.

Proposed future entry points:

```text
just doctor
just verify-inputs
just firmware
just image
just uki
just bundle
just factory-image
just lab-new <device-id>      # explicit provisioning, not ordinary boot
just lab-start <device-id>
just lab-stop <device-id>
just test-boot
just test-data
just test-update
just test-powercut
just test-attestation
just test-recovery
just reproducibility
just release-check
```

Signing commands must be separate from ordinary builds, with explicit approved key references. Destructive provisioning/reset/image-writing commands require a validated target and explicit confirmation; no broad disk globbing or automatic cleanup of the old research project.

## 10. Evidence and release artifact contract

Every run records:

- Test ID, date, source commit including reviewed patches, reviewer and expected result.
- Machine type/version, CPU/accelerator, memory, disk/flash layout, TPM frontend/backend versions and state identity.
- Firmware hash, expanded configuration, payload hash, trust fingerprints and relevant Secure Boot variables.
- OS/kernel/build ID, root/tree/UKI/RAUC hashes, slot and signed policy/security epoch.
- Exact commands, exit statuses, structured stages, timeouts, serial/QMP/system logs and measured packet timing where relevant.
- PCR bank/selection, sampling phase, quote challenge/result and event-log validation for TPM tests.
- Mutation location/before-after hashes for corruption tests, or transaction boundary/seed/cache model for power cuts.
- Actual result classified as PASS, FAIL, BLOCKED, HARDWARE-PENDING or historical/source-only evidence.
- Scope/limitations and the next action; preserve failed runs without relabeling them as successful.

Never log private keys, passphrases, recovery codes, live token authorizations or unredacted support sessions. State snapshots containing TPM secrets are private test assets, not public release evidence.

Required release outputs:

1. Firmware executable image/verified regions, public trust metadata, build configuration and source/patch manifest.
2. Unprovisioned factory disk image and layout specification.
3. Root filesystem and matching verity tree.
4. Signed systemd-boot, signed A/B UKIs and signed restricted recovery boot components.
5. Signed RAUC bundle plus compatibility and data-migration documentation.
6. CycloneDX SBOMs, license/source-offer materials and vulnerability/hardening assessment.
7. Reproducibility reports, signed checksums/provenance and test evidence index.
8. Provisioning, update, escrow, break-glass, recovery and firmware-restoration runbooks.
9. Hardware validation checklist and unresolved risk register.

Provisioned LUKS images, TPM state and recovery secrets are deliberately excluded from distributable factory artifacts.

## 11. Schedule, dependencies and review gates

Use the PDF's weeks as program alignment, not a promise that missing hardware work has already happened. Estimated sequencing assumes roughly one firmware engineer and two platform engineers, with security/build/test support; individual availability can change duration.

| Program window | Focus | Exit evidence |
| --- | --- | --- |
| Week 1 | Phases 0–1; preserve/reproduce useful research, portable locks and persistent harness | G0–G1; first firmware-root risks identified. |
| Weeks 1–3 | Phase 2; mkosi/kernel/verity work in Phase 3 starts from week 2 | G2–G3; controlled trust and deterministic root inputs. |
| Weeks 3–4 | Phase 4; installed systemd-boot A/B path | G4; no direct-UKI shortcut accepted. |
| Weeks 4–5 | Phase 5; real TPM measurements, signed policies and encrypted data | G5; escrow/transplant tests. |
| Weeks 5–7 | Phases 6–7; RAUC, health, rollback, data migration and early fault injection | G6–G7; broken signed update rolls back. |
| By week 6 | Firmware/ODM requirements handoff from A/B findings | Draft hardware requirements with explicitly pending sample evidence. |
| Weeks 6–8 | Phases 8–10; verifier, recovery, firmware updates and key lifecycle | G8–G10; B's week-8 review with pending hardware risks visible. |
| Weeks 2–10 continuously | Phase 11; reproducibility, hardening, CI and license/SBOM work | G11; C's week-10 image gate. |
| Weeks 9–10 | Phase 12 integrated fault/performance qualification | G12; reviewed QEMU release candidate. |
| Weeks 11–12 | R&D integration/exit review and hardware requalification if units arrived | Owned risks, updated findings, no false closure of other workstreams. |
| On hardware arrival | Phase 13 | G13; actual physical qualification. |

Critical dependency chain:

```text
portable pinned inputs + persistent Q35
  -> firmware trust + mkosi verified root
  -> signed systemd-boot/slot UKIs
  -> measured policy + encrypted data
  -> inactive-slot RAUC install + explicit activation
  -> health/rollback + compatible shared data
  -> recovery/key lifecycle/attestation
  -> integrated qualification + reproducibility evidence
  -> hardware-specific requalification
```

Do not defer the shared-ESP, pre-Linux rollback, TPM-policy-update or data-migration risks until the end; exercise each as soon as its first implementation exists.

## 12. Initial risk register and decision checkpoints

| Risk/decision | Owner role | Required resolution |
| --- | --- | --- |
| No real firmware root or fuse evidence in QEMU | Firmware/security | Label host-rooted model; qualify physical control in Phase 13. |
| vboot/EDK II/SMMSTORE combination and firmware-region capacity | Firmware | Feasibility test with pinned sources; record blocked firmware-verification claims, not a fake Secure Boot substitution. |
| Legacy dependencies/SDK are pinned but may be stale or incompletely authenticated | Build/security | Provenance/CVE review and deliberate refresh; pinning is not security approval. |
| Old project has ignored artifacts, local modifications and absolute/tool-hash dependencies | Platform | Inventory and portable reconstruction; do not overwrite or bypass its guards. |
| systemd 262 research stub versus systemd 257 root components | Platform | Align or explicitly qualify versions and PCR/cryptsetup compatibility. |
| No native systemd-boot slot semantics in selected RAUC EFI backend | Update engineer | Custom backend + two-stage activation + exhaustive integration tests. |
| Shared FAT ESP can be a common failure point | Platform/test | Power-loss gate; redesign if a candidate write can destroy the known-good path. |
| Default-entry semantics or automatic blessing defeats retry limit | Update engineer | Pinned-version boot-selection tests and one controlled health/blessing path. |
| Invalid EFI image fails before Linux watchdog exists | Firmware/test | Demonstrate actual firmware/boot-manager next-entry/reset coverage. |
| Raw PCR binding breaks updates/key rotation | TPM/security | Signed PCR11 policy, phase correctness and tested PCR7 transition procedure. |
| Shared data/schema migration breaks old root after rollback | Platform/application | Backward compatibility or transactional state generations before acceptance. |
| Signature authorization confused with anti-downgrade | Security/firmware | Separate installation version policy, authenticated revocation and any protected minimum epoch. |
| Recovery becomes a universal shell/unlock bypass | Security | Restricted signed recovery; operation/device-bound one-time authorization; separate escrow. |
| Escrow/header backups defeat naive reset/keyslot-revocation claims | Security/operations | Backup access, retention, rotation and reset semantics reviewed explicitly. |
| Full-root preverification threatens boot/downtime targets | Platform/performance | Measure/optimize; do not silently reduce integrity coverage. |
| HSM/discrete TPM/physical flash programmer not yet available | Release/hardware | Lab simulation labeled; no production custody or physical-recovery completion claim. |
| Unavailable business design and physical reference samples | Program lead | Obtain inputs; maintain explicit dependencies and update requirements through review. |

No further user choice blocks writing this plan. Implementation must still review the exact new tool/package lock, firmware-verification model, final layout sizing and production custody/retention procedures at their gates.

## 13. Definition of done

### QEMU milestone

- [ ] Standalone locked build and persistent Q35/swtpm environment; useful EXP-029 behavior accounted for.
- [ ] Source-built coreboot + UEFI; firmware trust boundary explicitly documented and independently tested where claimed.
- [ ] FireArc-owned Secure Boot trust; signed systemd-boot in the real path; unauthorized boot managers and UKIs refused.
- [ ] mkosi-built Debian with authenticated full-root preverification, read-only dm-verity, lockdown and documented kernel/modules.
- [ ] Unique TPM-bound LUKS2 data; allowed A/B boots unlock unattended; fresh-TPM transplant fails; escrow recovery works.
- [ ] Signed RAUC bundles update only the inactive pair; activation occurs only after complete validation.
- [ ] Correctly signed broken update rolls back unattended; health, counter, watchdog and shared-data semantics are proven.
- [ ] Required power-cut/ESP failure tests pass without hidden flash/TPM resets.
- [ ] Independent verifier checks fresh TPM quotes and rejects replay/identity/measurement substitutions.
- [ ] Signed restricted recovery, explicit reset, TPM-bound one-time break-glass and controlled escrow procedures tested.
- [ ] Signed firmware delivery/recovery and key/dbx/PCR-policy rotation tested at the declared emulator boundary.
- [ ] Reproducible payloads, CycloneDX SBOMs, license/source materials, hardening assessment and release provenance published.
- [ ] Real packet-based boot/update downtime measured against the PDF targets; exceptions recorded honestly.

### Hardware/production milestone — cannot be closed in QEMU

- [ ] FireArc-controlled physical firmware root and actual Boot Guard/fuse/ME status confirmed per sample.
- [ ] Discrete TPM2, SPI protections, UART/recovery path and watchdog behavior qualified per model.
- [ ] Real storage/flash power-loss and brown-out recovery tests pass.
- [ ] Hardware boot/update timing and model-specific driver behavior meet reviewed requirements.
- [ ] Production offline-root/HSM/two-person release and per-device escrow operations are operationally reviewed.
- [ ] G4/G6 firmware/ODM requirements and remaining risks are reviewed in the full R&D exit process.

## 14. Reference registry

The PDF and local research are the requirements/compatibility sources. Online documents explain component contracts; pin their applicable versions during implementation because `latest`, `main` and `master` can change.

### Local primary sources

- `FireArc_R-D_Plan—Technical_Team.pdf`, especially pp. 5–7 and 13.
- `/home/rifat/projects/project_firearc/docs/boot-chain-file-map.md`.
- `/home/rifat/projects/project_firearc/docs/experiments/EXP-029-authenticated-debian-root.md`.
- Exact dependency/configuration/evidence paths listed in Section 3.1.

### Upstream component contracts

- [coreboot Q35 documentation source](https://github.com/coreboot/coreboot/blob/main/Documentation/mainboard/emulation/qemu-q35.md).
- [coreboot EDK II payload configuration](https://github.com/coreboot/coreboot/blob/main/payloads/external/edk2/Kconfig); use the locked Dasharo tree for actual option compatibility.
- [coreboot vboot design](https://github.com/coreboot/coreboot/blob/main/Documentation/security/vboot/index.md).
- [coreboot measured boot](https://github.com/coreboot/coreboot/blob/main/Documentation/security/vboot/measured_boot.md).
- [coreboot SMMSTORE](https://github.com/coreboot/coreboot/blob/main/Documentation/drivers/smmstore.md); inherited pins use the older SMMSTORE v2 option naming.
- [EDK II UEFI payload](https://github.com/tianocore/edk2/blob/master/UefiPayloadPkg/Readme.md); do not substitute it blindly for the successful Dasharo payload.
- [QEMU TPM device and swtpm integration](https://www.qemu.org/docs/master/specs/tpm.html).
- [mkosi manual source](https://github.com/systemd/mkosi/blob/main/mkosi/resources/man/mkosi.1.md).
- [Debian trixie systemd-boot documentation](https://manpages.debian.org/trixie/systemd-boot/systemd-boot.7.en.html).
- [systemd automatic boot assessment](https://systemd.io/AUTOMATIC_BOOT_ASSESSMENT/).
- [systemd-stub and UKI external-input behavior](https://www.freedesktop.org/software/systemd/man/latest/systemd-stub.html).
- [systemd-cryptenroll PCR policies and compatibility](https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptenroll.html).
- [systemd verity generator](https://www.freedesktop.org/software/systemd/man/latest/systemd-veritysetup-generator.html).
- [RAUC integration: grouping, booted-slot detection and custom backend](https://rauc.readthedocs.io/en/latest/integration.html).
- [RAUC handlers, hooks and installation/marking APIs](https://rauc.readthedocs.io/en/latest/using.html).
- [RAUC signing, verity bundles and data migration](https://rauc.readthedocs.io/en/latest/advanced.html).

**Current implementation action:** Phase 0 documentation/input verification and Phase 1 persistent research harness are underway; see [progress](docs/progress.md). The portable mkosi builder and final installed-device profile remain ahead. Do not regenerate old keys, replace reference sources or launch a destructive installer to bypass an unmet gate.
