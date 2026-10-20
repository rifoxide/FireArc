# Development device boot validation

## Scope

`just device` assembles an unsigned development installed-device disk from the
frozen OS payloads, and `just check-boot` boots it under the pinned host QEMU
Q35/OVMF tools and asserts the initramfs integrity gate outcome on the serial
console. This is the development trust domain of the QEMU threat model: it is
not Secure Boot, not production provisioning, and not a physical-device or
release qualification. OVMF is the explicitly permitted initial QEMU firmware
fixture; the self-built coreboot/EDK II path remains open.

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

## Result (2026-10-20)

`just check-boot` passed on QEMU Q35 with KVM. Positive boot: full 4 GiB
verity preverification, dm-verity mapping, read-only ext4 sysroot mount and
the self-verified terminal marker, followed by clean poweroff. Corruption
control: one flipped bit at the root-partition midpoint produced
`Verification failed at position 2147483648` — exactly the flip offset — no
mapping, no mount and no terminal marker, followed by failure-path poweroff.
Both runs exited QEMU through poweroff rather than timeout.

The stage records the host QEMU and OVMF file digests, whether KVM was used,
and per-marker observations. Because initrd journald console forwarding
nondeterministically drops status lines, only the self-verified terminal
marker is authoritative for the positive verdict; other gate markers are
recorded as supporting evidence.

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

## Limits

Unsigned development profile (Secure Boot off, OVMF trust, development
authority segment, deterministic development GUIDs). Single machine, no
attestation, no A/B slot switching, no firmware measurement, no swtpm, no
runtime write-attempt or reboot-loop coverage. Serial evidence beyond the
console-direct marker is best-effort recorded, not guaranteed complete.
