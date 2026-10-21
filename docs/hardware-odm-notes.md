# Hardware / ODM transfer notes

Standing record for findings that matter when moving from the QEMU Q35
development harness to real hardware, or when writing firmware requirements
for an ODM. Each entry names where it was observed and what to verify on
target. Nothing here is a qualification claim; it is hard-won configuration
ground truth.

## Firmware payload (EDK II) procurement requirements

- **Demand a crypto library with real Authenticode verification, and verify
  it empirically.** The pinned Dasharo payload links
  `BaseCryptLibMbedTls`, whose `CryptAuthenticodeVerify` is an
  **unconditional stub returning FALSE**
  (`CryptoPkg/Library/BaseCryptLibMbedTls/Pk/CryptAuthenticode.c`). On that
  firmware, db **certificate** entries authorize nothing; only SHA-256
  **digest** entries work, so Secure Boot degrades to content anchoring and
  "who signed" is unprovable (ADR 0007, 2026-10-21). When evaluating an
  ODM firmware build: check the payload DSC (the real one here was
  `DasharoPayloadPkg/DasharoPayloadPkg.dsc`, *not* `UefiPayloadPkg.dsc`)
  and boot a test image whose signer certificate sits in db — it must be
  authorized.
- **Ask whether the firmware auto-enrolls a default key hierarchy on a
  pristine variable store.** Ours did (Dasharo PK/KEK/db/dbx on every
  pristine start). On real hardware that is either a feature (first-boot
  provisioning) or a liability (an authorization root we did not install);
  the store must be replaced wholesale before enforcement means anything.
- **Check who writes the `SecureBoot` variable.** Our payload never writes
  it; enforcement was dead until our offline enrollment set it. A payload
  deriving SecureBoot from `SecureBootEnable`
  (`gEfiSecureBootEnableDisableGuid`) each boot is easier to provision;
  know which model the ODM firmware uses.
- **Variable-store geometry and format must be extracted from the shipped
  image, not assumed**: FV header layout, `PcdVariableStoreSize` (64 KiB
  here), `ALIGNMENT 1` packing, entry header size (60 bytes) all mattered
  for offline enrollment (ADR 0007).

## coreboot vboot adoption constraints (observed 2026-10-21)

- **vboot RSA key algorithms are an enum, not arbitrary**: 1024, 2048,
  4096, 8192; 3072 only with **exponent 3** (`RSA3072_EXP3*`).
  `openssl genrsa 3072` (default e=65537) is rejected by `futility create`
  with "Unsupported sig algorithm in RSA key". Plan key sizes accordingly
  (we use root RSA-4096, firmware data key RSA-2048).
- **OpenSSL 3 writes PKCS#8 PEMs; futility wants PKCS#1.** Generate with
  `openssl genrsa -traditional` or convert before `futility create`.
- **futility builds offline from the pinned coreboot `3rdparty/vboot`**
  in the coreboot SDK container with `USE_FLASHROM=0` (libflashrom is a
  pkg-config dependency that will not resolve offline). On a real
  toolchain, pin the vboot sources the same way as everything else.
- **FMAP region sizing has compile-time couplings**:
  - `SMMSTORE` must be **64 KiB aligned** in the flash map
    (`drivers/smmstore/store.c` static assert).
  - `RO_FRID` and `RW_FWID_A` must fit the concatenation of
    `CONFIG_MAINBOARD_VENDOR` + `_` + `CONFIG_MAINBOARD_PART_NUMBER` +
    the coreboot version string — ours ("Dell Inc._QEMU x86 q35/ich9" +
    a long Dasharo version) overflowed the upstream 64-byte regions.
    Size them from the real strings (we use 0x100).
  - The 8 MiB budget: vboot RW_A (~3.7 MiB usable after VBLOCK) plus RO
    recovery CBFS fits the 1.13 MiB EDK II payload comfortably; RW_AB
    (~1.7 MiB per slot) is tight once stages join the payload.
- **VBNV persistence is board-dependent**: QEMU keeps no CMOS across
  process restarts, so `VBOOT_VBNV_CMOS_BACKUP_TO_FLASH` + an `RW_NVRAM`
  FMAP region is required; a real board may prefer EC/CMOS-backed VBNV.
  Decide with the ODM which backend carries try-count/state.
- **vboot without a TPM mocks secdata** (`VBOOT_MOCK_SECDATA` selected
  automatically when `!TPM`): anti-rollback is not real in that mode. On
  hardware, decide the TPM (and its coreboot driver) explicitly; remember
  the kernel-side duplicate-MSFT0101 ACPI artifact recorded in the device
  profile notes when the same TPM serves both coreboot and Linux.
- **Recovery payload is a design decision** (full EDK II payload vs a
  minimal recovery OS): boot time, attack surface, and how the recovery
  path is itself updated must be settled with the ODM.

## Build and signing pipeline

- The coreboot build signs **nothing** by itself: with `CONFIG_VBOOT=y`
  it emits the image with GBB/vblock regions created but the RW slot
  unsigned; runtime verification fails until `futility sign` runs. Keep
  signing a separate, custody-controlled stage (our `futility` stage
  builds the tool from pinned sources; the keyset lives under gitignored
  `secrets/vboot/`).
- `futility create` emits vb21 (`.vbprik2`/`.vbpubk2`) keypairs from PEMs;
  the legacy vb1 keyset layout (`root_key.vbprivk`/`.vbpubk`) is what
  `futility sign --keyset` lookups default to — match formats explicitly
  when scripting the signing step.
- Coreboot SDK image and payload workspace must be digest-pinned; the EDK
  II payload is pre-seeded into `payloads/external/edk2/workspace/` so no
  network fetch happens during firmware builds.

## Harness limits that disappear (or get worse) on hardware

- QEMU pflash has **no hardware write protection**: every "writes confined
  to region X" result is host-anchored evidence (ADR 0005). On hardware,
  WP_RO claims become real but must be requalified against the flash
  controller's protection registers (PR0-4, SMM write protection).
- The 108-byte UNIX socket path limit (kernel) bit us for long stage-dir
  names; irrelevant on hardware but a reminder that evidence-directory
  naming is part of the harness contract.
