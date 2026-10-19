# Appliance root: unsigned preassembly stage

This stage extends the mkosi [builder](builder.md) toward Phase 3. It is **not a
deployable or verified-boot image** and must never be used to bypass Secure Boot
or root verification. The existing QEMU regression fixture is unchanged.

## Separate package closure

`locks/root.json` requests exact versions of the Debian bring-up kernel,
systemd, dracut, verity/cryptsetup tools, TPM tools, RAUC and minimal network tools.
The maintained Debian kernel is a temporary baseline permitted by PLAN Phase 3;
it is not the final FireArc kernel/configuration. Its existing distribution
signature does not establish FireArc firmware trust.

The APT plan uses the same authenticated main/security snapshot as the tools
builder, but starts from an empty status and computes a separate root dependency
closure. Missing local packages cause failure; there is no live-mirror fallback.

```sh
just bootstrap
just build-root
just check-initrd
```

Successful dependencies are selected automatically. The root recipe receives its package list from
the exact profile lock. Input records pin the rendered recipe and package plan;
output records contain artifact hashes and selected tar inspections.

## Current boundaries

- Dracut includes the [project root gate](initramfs.md), Q35/device-mapper drivers,
  veritysetup and TPM support, with generic root/crypt/overlay/emergency paths
  omitted. Root is unencrypted; data unlocking remains a later explicit policy.
  Static/logic checks do not replace actual signed boot and failure-path tests.
- systemd-boot and stub binaries use the same pinned 257.13 version as userspace.
  They are present as inputs, **not yet installed in the observed boot path**.
- `Bootable=no`/`SecureBoot=no` describe a tar-stage output, not permission to boot
  an unsigned appliance. No ESP, UKI signatures, FireArc keys or device identities
  are created.
- RAUC is only installed; no bundle trust, slot layout, activation or rollback
  behavior has been configured or qualified. LUKS2/TPM policy is also pending.
- No module-lockdown, custom-kernel, firmware-root, CVE or production-release
  claim follows from the package/header/kernel-feature checks.

The [offline ext4/verity assembly](root-filesystem.md) freezes this tar into
full-range verified payloads. The dracut root gate is implemented; next assemble
slot-specific authority/UKI inputs and qualify the actual signed boot path.
Signed boot tests require separately approved signing
credentials; builds do not generate or access private signing keys.

Actual results and limitations: [appliance root validation](validation/appliance-root.md).
