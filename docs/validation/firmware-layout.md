# Firmware flash-layout validation

## Scope

`just firmware-layout` parses the flash map (FMAP) of the self-built 8 MiB
QEMU ROM offline, classifies every region by the role this harness depends
on, and archives the region inventory under `build/firmware-layout/`. The
parser is pure Python and validates the FMAP structurally: the magic byte
string also occurs inside firmware debug strings, so every candidate must
carry a supported version, describe the whole image, and present a bounded,
printable, uniquely named, in-bounds area table; exactly one valid map may
result. This is static layout evidence only: no boot, no flash write
protection, and no security review of the firmware.

## Observed layout (2026-10-20)

FMAP v1.1 at image offset `0x40000`, named `FLASH`, base `0xff800000`,
describing the full 8 MiB image. The child areas partition the image exactly
(no gaps):

| Region | Image range | Size | Role | Pristine content |
| --- | --- | --- | --- | --- |
| `BIOS` | `0x000000`–`0x800000` | 8 MiB | whole-flash container | — |
| `SMMSTORE` | `0x000000`–`0x040000` | 256 KiB | UEFI variable store; only guest-writable region | fully erased (`0xff`) |
| `FMAP` | `0x040000`–`0x040200` | 512 B | flash-map descriptor | the FMAP itself |
| `BOOTSPLASH` | `0x040200`–`0x080200` | 256 KiB | preserved/unused (bootsplash input declined) | erased except a 28-byte stale CBFS deleted-file marker |
| `COREBOOT` | `0x080200`–`0x800000` | 7,863,808 B | CBFS code: bootblock, romstage, ramstage, postcar, config, revision, build_info, DSDT, CMOS layout, EDK II payload | build output |

Recorded facts with direct plan consequences:

- **No vboot regions exist** in this pinned board layout: no `GBB`,
  `VBLOCK_*`, `RO_*` or `RW_*` area is present, so a protected-RO
  firmware-verification model (PLAN Phase 2 items 5–7) would require a board
  layout change before any signing attempt. Region names that merely sound
  verified are not firmware verified boot.
- **Boot-selection state has exactly one home**: systemd-boot's default entry,
  timeout and future try-counter state live in UEFI variables, which this
  layout carries only in `SMMSTORE`; there is no separate boot-state flash
  region to preserve or verify.
- **The variable store ships erased**, so the first boot initializes it; any
  pre-populated vendor variable state is therefore absent from the built image.

## Write confinement during baseline boots

`just check-boot` additionally requires each booted flash copy (positive and
corruption-control run) to differ from the pristine ROM **only** inside
`SMMSTORE`: every byte of `COREBOOT`, `FMAP`, `BOOTSPLASH` and any unmapped
gap must be identical after the run, with the offending area and offset
reported on violation.

Result (2026-10-20, KVM): both runs initialized the variable store with
33,586 changed bytes across the first 10 blocks (`0x0`–`0x1006a`) of
`SMMSTORE` and left every other flash byte unchanged. Both runs produced the
same post-boot `SMMSTORE` digest (`a31e5396a3d8f91f…`), so the first-boot
variable initialization was byte-identical between the two boots on this
host. Evidence lives in each check-boot stage result
(`flash_write_confinement`) alongside the boot verdicts.

## Limits

- QEMU pflash has no hardware write protection: this records where writes
  *did* land, not that unauthorized writes are impossible. A protected-RO
  model remains a separate, currently unimplemented qualification.
- Confinement is checked at process exit; writes made and reverted within a
  run are indistinguishable from no writes.
- One ROM (the pinned Q35 Dasharo variant at the locked commits) on one host;
  the deterministic variable initialization is an observation, not a
  reproducibility claim for firmware.
