# ADR 0008 — vboot protected-RW adoption on the Q35 firmware

**Status:** Accepted 2026-10-21 (chain step 4; PLAN Phase 2 items 5–6).

## Context

The enforced chain (ADR 0007) gates the OS boot path, but the firmware's own
mutable RW regions were unprotected: the pinned build was `CONFIG_VBOOT`-unset
with a flat `board.fmd`. The investigation
(`docs/validation/firmware-vboot.md`) established that the upstream
`emulation/qemu-q35` board ships first-class vboot support (RW_A layout,
`VBOOT_STARTS_IN_BOOTBLOCK`, VBNV CMOS), futility builds offline from the
pinned `3rdparty/vboot`, and the blockers were engineering: restoring SMMSTORE
(the UEFI variable store the enrollment chain writes) and flash-backed VBNV
(QEMU keeps no CMOS across process restarts).

## Decision

**Adopt vboot RW_A verification with a custom tracked flash layout, a
dedicated development vboot key hierarchy under `secrets/vboot/`, and two new
pipeline stages:**

1. **Layout** (`images/firmware/q35-vboot.fmd`, injected by the firmware-build
   stage at the exact `CONFIG_FMDFILE` path, digest pinned in the build
   manifest): upstream `vboot-rwa-8M` plus `SMMSTORE` 0x40000 (64 KiB aligned,
   a static assert in `drivers/smmstore/store.c`), `RW_NVRAM` 0x1000
   (`VBOOT_VBNV_CMOS_BACKUP_TO_FLASH`), and enlarged `RO_FRID`/`RW_FWID_A`
   (0x100 — the build's FWID string overflowed upstream's 64-byte regions).
   The config enables `CONFIG_VBOOT=y`; anti-rollback secdata runs against a
   real per-boot swtpm TPM (kernel versions are development values).
2. **Keyset** (`just vboot-keys`, ADR 0006 custody rules): root RSA-4096,
   firmware data key and kernel subkey RSA-2048 — vboot's algorithm enum has
   no plain RSA-3072 (only exponent-3) — generated as traditional PKCS#1 PEMs
   and converted to the vb1 keyset layout `futility sign --keyset` consumes,
   plus `firmware.keyblock` (data public key, signed by the root). PEM
   intermediates are deleted; only the keyset remains.
3. **`futility` stage**: the signing tool is compiled from the pinned
   `3rdparty/vboot` sources inside the pinned coreboot SDK container
   (`USE_FLASHROM=0`; libflashrom is an unresolvable offline dependency) and
   exported as a digest-pinned artifact.
4. **`firmware-sign` stage**: signs the firmware-build ROM's RW section with
   the keyset and — critically — **installs our root key into the GBB** with
   `gbb_utility -s --rootkey` (the coreboot build leaves the upstream vboot
   *test devkeys* root there, and `futility sign` never touches the GBB).
   Fails closed on `futility verify` and on confinement: only `GBB` and
   `VBLOCK_A` may change.
5. **`check-firmware-vboot` gate**: four QEMU sessions, each with a fresh
   swtpm (vboot secdata is per-machine) and `-no-reboot` for negatives.
   Verdicts: the signed image boots with **no recovery indication** (the RW
   verified and executed); tampered-RW (a flip inside the *signed body* —
   bytes beyond `Firmware body size` are unverified free space and flip
   harmlessly), attacker-keyed RW (throwaway keyset generated in the stage
   container, our GBB spliced back) and the no-recovery-payload variant all
   refuse with **no guest code executed** — either the vboot recovery reason
   on serial or an immediate reset with an untouched console. Flash writes on
   the good boot stay confined to SMMSTORE + RW_NVRAM.

## Observed consequences worth recording

- **A refused RW lands in recovery, and the RO recovery payload is the same
  full EDK II build** — it boots the OS chain (still gated by Secure Boot
  and the enrolled digests). The firmware-level refusal is proven by the
  recovery reason / reset behavior, not by a dead machine; the
  `tampered-no-recovery` session (recovery payload removed from a flash
  copy) provides the strongest form: with nothing to fall back to, a refused
  RW leaves the machine with no execution at all. Minimizing the recovery
  payload (attack surface, boot time) stays open for the ODM/hardware phase
  (see `docs/hardware-odm-notes.md`).
- **With an empty or foreign GBB root the RW verifies trivially**: the stock
  unsigned build executed its RW because the coreboot build had signed it
  with the embedded test devkeys and installed the devkeys root in the GBB.
  This is why the firmware-sign stage treats the GBB rootkey write as a
  required step, not cosmetic.
- The vboot verification does not extend to the RO region (host-anchored per
  ADR 0005: QEMU pflash has no write protection) and the layout
  classifier/write-confinement contract was requalified for the nested
  vboot map (`firmware_layout.classify` schema 2: permitted writable set is
  now SMMSTORE + RW_NVRAM).

## Consequences

- The boot chain is now firmware-verified from reset (vboot RW) through the
  boot manager and UKI (Secure Boot digest anchoring) to the read-only root
  (dm-verity) — every link with recorded rejection tests (gate G4 core).
- The firmware-build restages (config/fmd inputs changed); the old flat-layout
  firmware survives only as profile-pinned evidence and requalification of
  `check-boot`/`check-secure-boot`/device profiles on the vboot image is the
  immediately following step (PLAN §1.3 step 5).
- dbx policy, cold-start persistence and unauthorized variable-update refusal
  remain open as before; vboot measured-boot PCRs are extended by coreboot
  but not yet consumed by anything (attestation phase).
