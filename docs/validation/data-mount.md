# Crypttab unlock and encrypted data mount validation

Q35 + KVM + isolated swtpm; development keys only. Extends
[data provisioning/enrollment](data-provisioning.md) and
[ADR 0012](../decisions/0012-crypttab-data-mount-gate.md).

## Live-path evidence

Profile `data-verified`, factory device stage `device-382c9d67f80c`:

| Run | Operation | Observed result |
| --- | --- | --- |
| 0001 | Explicit enrollment | Filesystem birth, `FIREARC_DATA_ENROLL_OK`, `FIREARC_DATA_UNLOCK_OK`, `FIREARC_DATA_MOUNT_OK`. |
| 0002–0003 | Independent cold starts | Exactly one mount-success marker per boot, no enrollment, no unlock-refusal marker; host header/TPM/flash continuity passed. |
| 0004 | One warm reset (two boots in one QEMU session) | Exactly two mount-success markers, no enrollment or refusal. Each boot's verdict is checked independently. |

The profile records ext4 mounted at `/data` with `rw,noexec,nodev,nosuid`.
The guest gate checks these options and the mapper source in `/proc/mounts`
before emitting mount success. TPM unlock is performed by the generated
crypttab unit, not the observation-only probe. The payload can change while the
LUKS header/keyslot-area digest remains stable.

Latest-build gates passed:

- `check-initrd-3ae61301735d`: executable tools/scripts (data scripts also
  byte-checked against their build-input snapshot), cryptsetup generator,
  `mke2fs` plus `mkfs.ext4` symlink, root-gate units.
- `check-boot-6b78c417ddc2`: factory boot, preverification and runtime dm-verity
  corruption refusals.
- `check-secure-boot-34c9e1d6ffcd`: enforced Secure Boot and its rejection cases.
- `check-firmware-vboot-11d021405132`: firmware authorization positive/negative cases.
- `just verify-build`: all current recorded stage evidence verifies.

## Permitted lab image transition

Profile `data-updated` uses the latest factory OS/firmware code, with
`data-verified`'s data partition, recovery credential, TPM state and UEFI variable
store explicitly carried over. Two cold boots passed without enrollment; the
existing LUKS header/keyslot digest was unchanged. This exercises the same token
with a subsequent authorized UKI and retained device identity. Both systemd
versions are still 257.13. It is **not** a moved-disk test (the TPM state was
intentionally retained), a distinct-systemd-version compatibility test, a RAUC
transaction, or A/B/fallback qualification. Only disposable test profiles were
modified.

## Filesystem failure experiment

On disposable profile `data-path3`, snapshot `mounted-baseline`, overwrite
1024 bytes of ciphertext covering the ext4 primary superblock, leaving the LUKS
metadata/keyslots intact. Run 0004 failed the boot contract with
`FIREARC_DATA_UNLOCK_REFUSED` when the required data mount failed. The entire
data partition digest after the failed boot exactly equaled the corrupted
pre-boot digest: **no formatting, reset, or plaintext fallback** occurred.
Restoring the snapshot and booting again (run 0005) passed. This experiment
preceded the final blank-factory classifier fix; the final source retains the
same enrolled-volume mount path. It is a mount-failure test, not evidence for
the full wrong-PCR/absent-TPM matrix.

## Automated proof

The offline suite has 259 passing tests, including executable shell fixtures,
not only unit-string checks:

- No filesystem birth without the explicit initial transport grant.
- Existing ext4 survives an enrollment retry; foreign signatures and failed
  probes cannot cause formatting; failed mkfs never proceeds to enrollment.
- Recovery-file cleanup on both successful and failed enrollment.
- Failed crypttab mount cannot start a formatter or direct attach fallback.
- Wrong source/type or any missing mount restriction is refused.
- Blank-factory acceptance requires a whole-partition zero comparison, even
  when blkid returns success for GPT metadata without a TYPE.
- Writable ciphertext beyond the LUKS payload offset does not trip identity
  checks; changed keyslot material beyond the first MiB does.
- An enrolled boot requires both unlock and mount markers, independently of
  operation-history retention. The host never stops between those two markers.

## Reproduce

```sh
just check
just build
just stage check-initrd
just check-boot
just check-secure-boot
just check-firmware-vboot
just device-provision --name data-test
just data-enroll --name data-test
just device-boot --name data-test --count 2
just device-reboot --name data-test --resets 1
just verify-build
```

Use a new name: provisioning is explicit and must not replace an existing device
without owner authorization. Failed initial filesystem creation may require
explicit re-provisioning; automatic retries never receive a second format grant.

## Still open

- A distinct retained/candidate systemd-version pair unlocking the same token:
  only the current pinned 257.13 implementation is qualified.
- Real service consumers/bind mounts and full switch-root appliance behavior:
  the current harness deliberately remains in the initrd.
- A/B release/update/fallback, the complete TPM/PCR refusal matrix, approved
  escrow recovery and credential rotation, header-backup custody and retention,
  quotas/log-retention sizing. No G5-complete or production qualification claim.
