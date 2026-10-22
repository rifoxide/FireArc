# ADR 0012 — Crypttab-driven data unlock and required initrd mount

**Status:** Accepted (development Q35 harness). Extends ADR 0011.

## Decision

Use the pinned systemd 257.13 `systemd-cryptsetup-generator` and `/etc/crypttab`
inside the signed UKI. The generator emits the concrete
`systemd-cryptsetup@firearc\x2ddata.service`; Debian does **not** supply an
on-disk template to copy into the initrd.

The crypttab entry uses `noauto,nofail,tpm2-device=auto,headless`. Only the
FireArc mount gate starts `sysroot-data.mount`, which requires the generated
cryptsetup service. Its drop-in requires and orders after verified
`sysroot.mount`, `systemd-pcrphase-initrd.service`, and the enrollment unit.
This keeps real TPM unsealing after root verification and `enter-initrd`.
Neither a password prompt nor an automatic dracut crypt path is enabled.
The generator and binaries are installed explicitly; dracut's crypt modules
remain omitted.

The gate mounts ext4 at `/sysroot/data` (`/data` after switch-root), with
`rw,noexec,nodev,nosuid`. It verifies the actual mapper source, filesystem type,
and every required option in `/proc/mounts`. Failed unlock/mount triggers the
existing fail-closed poweroff unit. The immutable root supplies the mountpoint;
normal boot never creates one or formats anything. There are currently no
persistent service consumers, so there are no service bind mounts to add yet.
Future consumers must explicitly require the data mount; a blanket writable
`/etc` or `/var` overlay is not authorized.

An entirely zero-filled factory partition, or an intact recovery-only LUKS2
volume without a TPM token, may boot the development read-only root without
mounted data. `blkid` may return success for partition metadata without TYPE;
that is accepted only after a whole-partition comparison with `/dev/zero`.
An enrolled profile's host boot contract requires both unlock and mount markers:
missing tokens, missing disks, wrong sources/options, and failed mounts cannot
pass that contract. Without a mount the underlying `/data` directory remains
on the verified read-only root, not a writable fallback.

## Filesystem birth and retries

The explicit enrollment session also initializes the filesystem. A nonsecret
format-once grant occupies transport block 2, after the existing magic and
recovery credential blocks. The host persists `filesystem_init_started` before
sending this grant, and never grants formatting on retry. This deliberately
prefers an operator-visible refusal over reformatting after an ambiguous crash.
Retries may reuse a recognized ext4 filesystem; foreign signatures, probe errors,
and unreadable filesystems without the initial grant fail closed. Normal boot
never receives a grant. No `mkfs -F` is used.

The enrollment unit has `RemainAfterExit=yes`, so the mount dependency cannot
execute enrollment a second time in the same boot. The transport has an explicit
QEMU serial and is read through `/dev/disk/by-id/ata-QEMU_HARDDISK_FIREARC_ENROLL_V1`:
AHCI discovery can swap `/dev/sda` and `/dev/sdb`. The recovery file is always
scrubbed on script exit; the host scrubs the transport after the session.

## Mutable payload, immutable identity

Before enrollment the entire partition must stay unchanged. Once data is
mounted read-write, the encrypted payload is mutable by design. Identity checks
then cover both LUKS metadata copies **and all keyslot material**, up to the
validated crypt-segment payload offset, not merely the first MiB used to parse
JSON. The host persists this header digest and checks it at load/session start.
Enrollment state comes from durable keyslot/token records, not the bounded
operation history. Legacy profiles without the scoped digest retain their
whole-partition checks; they are not silently reformatted or migrated.

## Qualification boundary

See [data mount validation](../validation/data-mount.md). The current pinned
version, cold/warm boots, factory boot, and failed filesystem mount are qualified.
A distinct retained/candidate systemd-version pair, service bind mounts when
consumers exist, the complete policy-refusal matrix, escrow, and A/B update
qualification remain separate unfinished work. This ADR does not implement
Phases 6–13 or assert G5 completion.
