# Development device boot validation

## Scope

`just device` assembles an unsigned development installed-device disk from the
frozen OS payloads, and `just check-boot` boots it under the pinned host QEMU
Q35 with the self-built coreboot/EDK II firmware (`just firmware-build`) and
asserts the initramfs integrity gate outcome on the serial console. This is the
development trust domain of the QEMU threat model: it is not Secure Boot, not
production provisioning, and not a physical-device or release qualification.
The host OVMF compatibility fixture was replaced by the self-built firmware;
firmware-verified-boot claims remain open.

## Harness construction

- GPT disk (4,738 MiB) with `FIREARC_ESP` (512 MiB), `FIREARC_ROOT_A`
  (4 GiB) and `FIREARC_HASH_A` (128 MiB) on one disk, exact sector geometry
  recorded in the stage manifest. Fixed development partition GUIDs keep the
  harness reproducible; production provisioning assigns fresh identities.
- ESP populated with systemd-boot extracted from the same frozen root archive,
  a slot-A loader entry with the gate's required kernel command line, the
  kernel, and the initramfs extended by a deterministic development cpio
  segment (4-byte-aligned per the kernel's concatenated-initramfs rules).
- The development cpio carries the slot-A verity authority rendered by the
  strict text contract and an explicit development-only poweroff unit that
  independently re-checks `/proc/mounts` for the read-only verified sysroot
  before writing the terminal marker directly to the console device. It is
  never part of the signed pipeline.
- Firmware: the monolithic 8 MiB coreboot ROM (Dasharo Q35 UEFI variant at the
  pinned commits, compiled offline in the pinned SDK container) is booted as a
  single writable pflash copy per run; its SMMSTORE FMAP region carries the
  UEFI variable store, so there is no OVMF-style CODE/VARS split to persist.
  The payload has no virtio drivers, so the development disk is attached over
  the emulated ICH9 AHCI controller.

## Result (2026-10-20)

`just check-boot` passed on QEMU Q35 with KVM, both under the previous host
OVMF fixture and with the self-built coreboot/EDK II firmware. Positive boot:
full 4 GiB verity preverification, dm-verity mapping, read-only ext4 sysroot
mount and the self-verified terminal marker, followed by clean poweroff.
Corruption control: one flipped bit at the root-partition midpoint produced
`Verification failed at position 2147483648` — exactly the flip offset — no
mapping, no mount and no terminal marker, followed by failure-path poweroff.
Both runs exited QEMU through poweroff rather than timeout.

The stage records the host QEMU digest, the firmware ROM digest with its SDK
image and source counts, whether KVM was used, and per-marker observations.
Because initrd journald console forwarding nondeterministically drops status
lines, only the self-verified terminal marker is authoritative for the
positive verdict; other gate markers are recorded as supporting evidence.

Two independent full builds from the same pinned inputs on this host
(fresh source acquisition, separate build trees) produced **byte-identical**
8 MiB ROMs (`e2e1cc045baa84a4afb37a62d3468617770e71add0c7941b13634489c3da1176`):
coreboot derives `SOURCE_DATE_EPOCH` from the pinned commit date and the
container environment is pinned, so the compile is deterministic here. This
is a single-host observation, not the formal firmware reproducibility
qualification (fresh host/toolchain variant, diffoscope review, cross-machine
rebuild) required before release claims.

## Defects found and fixed by this qualification

The harness was the first execution of the gate outside static analysis and
found four real defects, each now covered by offline tests:

1. The gate raced boot-media enumeration; a bounded label-wait replaced the
   single settle call.
2. efivarfs was not mounted in the initrd, so loader-identity evidence was
   unreadable; the gate now mounts it and still fails closed without it.
3. systemd-boot renders `LoaderDevicePartUUID` with uppercase GUID hex while
   `blkid` reports lowercase; the ESP identity comparison now accepts exactly
   the two whole-string byte patterns without decoding variable contents.
4. `veritysetup open` was invoked with a nonexistent `--readonly` option;
   dm-verity mappings are read-only by construction and the existing
   post-open `blockdev` checks enforce that property.

The firmware build itself found one further configuration defect: omitting the
upstream `CONFIG_EDK2_SECURE_BOOT_DEFAULT_ENABLE=n` line let the payload
auto-enable Secure Boot with Microsoft default keys and deny the unsigned
development loader; the configuration now pins the upstream default-off state
and an offline test refuses any configuration that re-enables unpinned inputs.

## Limits

Unsigned development profile (Secure Boot support compiled in but disabled
without enrollment, development authority segment, deterministic development
GUIDs, host-rooted QEMU trust). Single machine, no attestation, no A/B slot
switching, no firmware measurement, no swtpm, no runtime write-attempt or
reboot-loop coverage. Firmware reproducibility is observed on one host only.
Serial evidence beyond the console-direct marker is best-effort recorded, not
guaranteed complete.
