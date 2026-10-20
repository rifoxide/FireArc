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
- Persistent installed-device profile (`just device-provision`/
  `just device-boot`): a per-device directory carries the OS disk, the
  writable firmware copy and one isolated swtpm TPM 2.0 state dir across cold
  starts. Two cold-start boots each reached the verified-root marker, bound
  the TPM through ACPI/TIS (`tpm_version_major=2`, `/dev/tpm0`, `/dev/tpmrm0`)
  and confined all flash writes to SMMSTORE; SMMSTORE and TPM state carried
  over between boots byte-exactly and are asserted stable outside guest
  execution. Found and fixed on the way: a dev-unit shutdown race against
  `switch_root` (now `poweroff -f`). See
  [device-profile validation](validation/device-profile.md).
- Explicit device lifecycle operations over a local-only QMP socket
  (`just device-reboot`/`device-stop`/`device-powercut`/`device-snapshot`/
  `device-restore`), closing gate G1: a warm-reset loop kept flash/TPM
  powered through three boots in one session (markers each boot, NVRAM
  carried and evolved); an abrupt power cut after a verified boot was
  recovered from on the next cold start with no silent NVRAM/TPM reset; state
  restoration happened only by explicit snapshot restore, and a failed
  session adopts its observed identity with an explicit failed record. Two
  real appliance findings recorded honestly: the payload intermittently
  parks at its interactive boot menu (mostly from pristine variable stores,
  once from an initialized one; harness sends a bounded, recorded ENTER over
  QMP), and the ACPI power button is not handled by the minimal root
  (`device-stop` records it and stops the machine itself). Orphaned
  QEMU/swtpm now die with the harness (`PR_SET_PDEATHSIG`).
- Phase 1 complete: TCG and KVM are distinct qualified profiles
  (`device-boot --tcg`, per-run `accel` records; ~75 s vs ~23 s per verified
  cold boot), persistent monolithic flash carries across cold starts and
  warm-reset loops (PLAN 1.12), and no session ever has a network device
  (`-net none`, PLAN 1.15).
- Post-mapping runtime corruption gate (PLAN Phase 3 item 12 complete): the dev
  unit now blocks `initrd.target` (requires + Before), so after the verified
  markers it can drop caches and re-read the whole verity-mapped root while
  the machine is still up; `check-boot` gained a third discipline that flips
  a root byte mid-session after the mapping is up — dm-verity returned an
  I/O error (`FIREARC_RUNTIME_CORRUPT_EIO`) while the uncorrupted control
  read clean. Found and fixed while qualifying: `dd` is absent from the
  minimal dracut initramfs (the read uses coreutils cat), and the unit's old
  guest-side poweroff was dead code anyway (switch_root stops the unit
  before it runs).
- Firmware evidence capture completed and a third byte-identical build
  (PLAN Phase 2 items 2 and 7): the firmware-build stage now archives the
  expanded Kconfig, the payload DSC/FDF (resolved from the DSC's
  FLASH_DEFINITION), an explicit empty patch record, and per-step
  build-command digests; the rebuilt ROM reproduced `e2e1cc04…` byte-for-byte
  and passed the full three-discipline check-boot gate again. ADR 0005
  records that the initial firmware verifier in QEMU is host-anchored only —
  no verified-boot claims until a protected-RO layout, signing keys and
  their own qualification exist.
- vboot adoption investigated (PLAN Phase 2 item 5,
  `docs/validation/firmware-vboot.md`): the pinned board ships upstream vboot
  machinery (config + RW_A/RW_AB 8 MiB layouts); adoption needs a custom fmd
  restoring SMMSTORE, flash-backed VBNV under QEMU, a recovery payload
  decision and — the blocker — a vboot signing key hierarchy.
- Bounded evidence retention (`just prune`): every successful stage build now
  prunes superseded evidence directories (keeps current + previous per stage),
  never touching device-profile-pinned provenance; the first run freed
  149 GB accumulated by whole-project-digest stage rebuilds.
- Development installed-device profile (`just device`): a GPT disk with ESP,
  slot-A root and hash partitions assembled offline from the frozen payloads,
  with systemd-boot taken from the same root archive.
- QEMU Q35 boot gate verification (`just check-boot`): the development disk
  boots through systemd-boot on the self-built coreboot/EDK II firmware; the
  initramfs gate performs full verity preverification, read-only mapping and
  sysroot mount, with a corrupted-root negative control that is denied at the
  exact flip offset. Runtime execution found and fixed four real gate defects.

## Validation

The label-free bootstrap/build/verification pipeline and 137 offline tests pass.
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
