# vboot adoption investigation for the pinned Q35 firmware

## Scope

Investigation only (PLAN Phase 2 item 5): what adopting coreboot vboot
protected-RO verification on the pinned `emulation/qemu-q35` board would
actually require. Nothing is adopted, signed or trusted here; the current
pinned build stays `CONFIG_VBOOT`-unset with the plain `board.fmd` layout.

## Findings (pinned coreboot tree, 2026-10-20)

1. **The board has first-class upstream vboot support.**
   `src/mainboard/emulation/qemu-q35/Kconfig` offers `VBOOT` with
   `VBOOT_STARTS_IN_BOOTBLOCK`, `VBOOT_VBNV_CMOS` and shipped FMAP layouts:
   `vboot-rwa-8M.fmd` (one RW slot, default) and `vboot-rwab-8M.fmd`
   (A/B RW slots), both sized for our 8 MiB flash. `FMDFILE` switches
   automatically with the slot choice. Adoption is a configuration and
   layout change, not new board porting.
2. **FMAP capacity works for RW_A, tightly for RW_AB.** RW_A gives a
   3.75 MiB `FW_MAIN_A` (the Dasharo EDK II payload is 1.13 MiB as a simple
   ELF, so stages plus payload fit comfortably). RW_AB gives ~1.69 MiB per
   slot after the 64 KiB `VBLOCK` — tight once romstage/ramstage join the
   payload; verify by trial build before choosing A/B.
3. **The shipped vboot layouts have no SMMSTORE region.** UEFI variable
   persistence (and the profile continuity evidence built on it) requires a
   custom fmd that adds SMMSTORE alongside the vboot regions, shrinking
   another region to compensate. This also forces requalifying the
   firmware-layout classification and the write-confinement gate against the
   new region map.
4. **TPM support exists for the anti-rollback/measured path.** The board
   selects `MEMORY_MAPPED_TPM` and its devicetree instantiates
   `drivers/pc80/tpm` — the MMIO TIS driver that binds QEMU's `tpm-tis`
   (backed by the device profile's swtpm). vboot can therefore use TPM NV
   and measured boot in the harness; this is coreboot's own driver and is
   unrelated to the kernel-side duplicate-MSFT0101 ACPI artifact recorded in
   the device-profile findings.
5. **VBNV persistence needs a flash-backed option under QEMU.** The board
   selects `VBOOT_VBNV_CMOS`, but QEMU provides no persistent CMOS across
   process restarts, so vboot try-count/result state would reset every cold
   start. `VBOOT_VBNV_CMOS_BACKUP_TO_FLASH` (or `VBOOT_VBNV_FLASH`) must be
   enabled — and the backup region then joins the write-confinement contract.
6. **Recovery needs a decision.** The RO `COREBOOT` CBFS (~3.9 MiB) carries
   the recovery firmware; reusing the full EDK II payload fits, but whether
   recovery should be the full payload or a minimal one is an open design
   choice with boot-time and attack-surface implications.
7. **Signing tooling is available offline.** The pinned closure already
   includes `3rdparty/vboot` (f1f70f46…); futility/vbutil_* can be built from
   those sources, so signing does not require network access.

## Adoption prerequisites

| Step | Status |
| --- | --- |
| Custom fmd (SMMSTORE + slot choice) and `CONFIG_VBOOT=y` | unblocked engineering |
| VBNV flash persistence under QEMU | unblocked (config option exists) |
| TPM binding (swtpm TIS via `drivers/pc80/tpm`) | unblocked, already qualified at the OS level |
| Recovery payload decision | design decision for the owner |
| vboot key hierarchy (GBB root key, firmware signing keys) | **blocked on the development key hierarchy/custody decision** (Phase 2 items 9–11) |
| Requalification: layout classification, write confinement, three-discipline check-boot, profile continuity | unblocked once a vboot image is built |

## Conclusion

Adopting vboot is feasible exactly because upstream ships the machinery for
this board, but it is a real board-layout change: a custom fmd restoring
SMMSTORE, flash-backed VBNV, a recovery payload choice, and — the hard
blocker — a vboot signing key hierarchy. Per ADR 0005, even a vboot-enabled
QEMU image remains host-anchored: it can demonstrate mechanism and negative
controls (modified/wrong-key RW rejection before payload execution, PLAN
item 6), never resistance to a malicious host.
