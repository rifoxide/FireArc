# Verified-root initramfs

`images/initrd/99firearc-root/` contains the project-owned dracut module. It is
built into the [appliance root stage](appliance-root.md) but is **not qualified
for deployment** until the installed signed boot path and failure matrix pass.

## Root mount gate

1. Read `/etc/firearc/verity.authority` from the initrd, never from a root/hash
   partition, ESP metadata or arbitrary command-line file. The parser accepts a
   small exact schema, a slot A/B selector, SHA-256 values and the fixed 4 GiB/
   128 MiB format. Unknown, duplicate, truncated, oversized, binary or malformed
   inputs fail. No `source`, `eval` or executable configuration is used.
2. Require matching slot/mapper/root-type/read-only kernel arguments and disabled
   shell defaults. Reject duplicates, raw-root, writable and recognized debug/init
   overrides. Those arguments must ultimately be covered by the UKI signature.
3. Resolve exactly one matching root, hash and ESP partition. Reject missing or
   duplicate labels, wrong sizes and partitions on different parent disks.
4. Compare the selected ESP's PARTUUID with the boot loader's
   `LoaderDevicePartUUID` EFI variable. Missing/malformed/mismatched values fail.
   This binds selection to boot metadata, not to a `/dev/sda` ordering assumption.
   The EFI variable is **not an independent root of trust or device identity**;
   correct handoff from signed systemd-boot/stub must still be qualified.
5. Refuse an existing `firearc-root` mapping. Mark the selected data/hash
   partitions read-only, fully verify every protected block using the embedded
   digest/salt/geometry, then open a read-only dm-verity mapping. No corrupt-data
   ignore option, raw-root retry or writable mapping is accepted.
6. `sysroot.mount` requires the successful gate and mounts only that mapping as
   ext4 with `ro,noload`, preventing journal replay into the frozen filesystem.

The required oneshot has a bounded start timeout. Integrity/mount failure selects
the no-shell poweroff path; this is **not yet health-gated A/B fallback**. Runtime
dm-verity corruption uses ordinary I/O denial; watchdog/slot behavior is still
separate integration work.

## No alternate initrd root path

The module installs high-priority units in `/etc/systemd/system`, requires the
verified mount from `initrd-root-fs.target`, masks emergency/rescue/debug shells
and disables automatic GPT/fstab/verity/debug root generators in the initrd.
The profile omits generic rootfs-block, dracut-systemd, overlay and emergency
modules rather than leaving a second root-mount implementation available.

Dracut's generic crypt modules depend on that omitted rootfs-block path, so they
are also omitted from this **unencrypted-root** initrd. TPM support and the root
filesystem's LUKS2 tooling remain present. Persistent-data unlocking still needs
its explicit PCR policy and controlled, noninteractive integration; it is not
implemented by an automatic initrd crypttab prompt.

## Authority and signing order

The generic initrd deliberately has **no authority file** and must fail if booted
without the slot-specific content. `render_initrd_authority` in
`src/firearc/rootfs.py` renders the validated payload geometry/digest for
the shell parser. Subsequent UKI assembly must embed that file only after the
root filesystem is frozen and the tree is generated. The final UKI signature
must cover both the gate and authority, and the Secure Boot path must enforce it.
Do not treat an unsigned JSON/text authority file as authenticated boot input.

Changing module contents changes the built root stage. Rebuild/freeze dependent
root payloads before deriving their authority; never patch a filesystem after
its verity hash is finalized.

## Checks

```sh
just check
just build-root
just check-initrd
```

The pipeline selects the current root automatically. The static checker verifies exact
embedded scripts/units against the copied build inputs, executable entry-point
mode, required/forbidden modules, required mount dependency, no-shell masks and
absence of generic slot authority. It also unpacks into a disposable container
tmpfs and verifies the actual embedded units using pinned systemd. The tmpfs is
executable for systemd's access checks; units are not started. The checker never
boots or activates a mapping and has no network, host block devices or capabilities.

`tests/test_initrd.py` executes the actual shell library using synthetic tool/
block backends. Those tests check parsing, ordering and denial logic without
touching real EFI state, block devices or device mapper. They are not boot tests.

Remaining: slot-authority/UKI assembly, actual systemd/udev/unit scheduling and
EFI handoff tests, corruption/missing-device/timeout/mount-failure boots, signed
module/lockdown checks and bounded A/B recovery. See
[component validation](validation/appliance-root.md).
