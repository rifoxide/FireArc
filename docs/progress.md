# Implementation progress

**Updated:** 2026-10-20. **Stage:** build-system restructuring and clean-build
qualification. The complete secured appliance is not yet implemented.

## Implemented

- Project-owned source package under `src/firearc/`, image policies under
  `images/`, a pinned builder under `containers/builder/`, and exact input locks.
- Label-free build commands, automatic dependency resolution/build IDs,
  input-sensitive cache invalidation and verified success receipts.
- Public upstream bootstrap: digest-pinned Debian image/keyring, signed snapshot
  metadata, complete package-closure fingerprints and size/SHA-256 checks.
- Offline tools build and rootless mkosi kernel/root/initramfs assembly.
- Fixed 4 GiB ext4 payload, headerless verity tree and explicit hash/geometry.
- Initramfs gate with strict embedded authority and slot/command-line checks,
  same-disk/boot-ESP validation, full preverification, read-only mapping/mount,
  no raw-root fallback and no-shell failure units.
- Static embedded-code/unit audit and copied-payload corruption controls.
- Clean/reproduction commands that rebuild from empty project output directories.
- Preliminary CycloneDX 1.5 inventory of the locked root closure (`just sbom`),
  with a deterministic serial number derived from the closure fingerprint.
- Exact-commit acquisition of the pinned upstream firmware repositories
  (`just firmware-sources --online`), with per-source tree records and offline
  re-verification. The fourteen pinned submodules are materialized inside the
  coreboot/EDK II checkouts under a gitlink census enforced against each parent
  tree, declining every unlisted upstream submodule. Nothing is trusted yet.
- Self-built QEMU Q35 firmware (`just firmware-build`): the pinned closure
  compiles offline in the pinned coreboot SDK container into the monolithic
  8 MiB ROM with the EDK II payload, with manifest-bound inputs, toolchain
  digests and CBFS inventory. `just check-boot` now boots the self-built
  firmware (writable SMMSTORE pflash, AHCI disk) instead of host OVMF; the
  integrity gate passes and the corruption control still denies.
- Firmware flash-layout inspection (`just firmware-layout`): the ROM's FMAP is
  parsed and archived offline with region roles — SMMSTORE variable store,
  FMAP descriptor, preserved BOOTSPLASH, COREBOOT CBFS code; no gaps and no
  vboot regions exist in the pinned layout. The boot gate additionally
  requires every flash byte outside SMMSTORE to survive each run unchanged;
  both baseline boots confined 33,586 bytes of variable initialization to
  SMMSTORE (see [firmware-layout validation](validation/firmware-layout.md)).
- Development installed-device profile (`just device`): a GPT disk with ESP,
  slot-A root and hash partitions assembled offline from the frozen payloads,
  with systemd-boot taken from the same root archive.
- QEMU Q35 boot gate verification (`just check-boot`): the development disk
  boots through systemd-boot on the self-built coreboot/EDK II firmware; the
  initramfs gate performs full verity preverification, read-only mapping and
  sysroot mount, with a corrupted-root negative control that is denied at the
  exact flip offset. Runtime execution found and fixed four real gate defects.

## Validation

The label-free bootstrap/build/verification pipeline and 106 offline tests pass.
The fresh-clone build/verification passed, and `just reproduce --yes` completed
two empty-cache download/build/verification rounds with **byte-identical
payloads** (kernel, initramfs, root tar, ext4, verity tree, authority). The
earlier failures from unsorted tar members and an unpinned ext4 directory-hash
seed are fixed. Scope limits (single host/Python, preserved Docker content
cache, OS payloads only) are recorded with the result.
The development device boot gate passed under QEMU Q35 with KVM, first under
the host OVMF fixture and then with the self-built coreboot/EDK II firmware,
including the corrupted-root denial control; see
[device boot validation](validation/device-boot.md) for evidence and limits.
Results are recorded in [build-system validation](validation/build-system.md)
and [root validation](validation/appliance-root.md); no unrun clean-build or
byte-reproducibility result is implied by the implementation list above.

## Next gates

1. Assemble slot-specific signed UKI inputs and qualify the signed boot path;
   post-mapping runtime corruption reads and the authenticated fallback
   interface remain untested.
2. Implement the pinned source-built firmware path and qualify firmware trust,
   authenticated variables and unique TPM ACPI/event-log ownership.
3. Implement installed A/B storage, TPM-bound LUKS2/escrow, RAUC activation/health/
   rollback, attestation, restricted recovery and release hardening/CI.

G0/G1/G3 and later acceptance gates remain open. Hardware, legal review,
production signing custody and external design documents are still dependencies.
Git commit signing is temporarily deferred under ADR 0004; boot/update/release
signatures are not waived.
