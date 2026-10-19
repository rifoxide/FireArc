# Initial threat model

**Scope:** QEMU B/C research, not a production hardware security certification.

## Assets

- Integrity/authorization of firmware, boot manager, UKI, root and updates.
- Availability of a permitted fallback, including interrupted-update recovery.
- Confidentiality of persistent device/tenant data and recovery credentials.
- Per-device identity, fresh attestation and trustworthy release/provisioning logs.
- Private signing keys and two-person authority over destructive/recovery actions.

## Trusted components in this milestone

The host OS/user, QEMU and its libraries, approved initial coreboot/EDK II fixture,
imported signed binaries and their pinned manifests, the harness, and swtpm state
custody are trusted. Exact hashes detect accidental substitution; the historical
manifest pins are a reviewed research trust anchor, **not verified publisher
signatures or proof of source reproducibility**.

A host administrator can replace firmware, alter tests, clone software-TPM state
or restore an entire old VM. Ordinary QEMU cannot enforce confidentiality,
physical-device binding or anti-replay against that administrator.

## Attacker capabilities to qualify

| Capability | Intended defense | Current foundation |
| --- | --- | --- |
| Alter/replace UKI on media | UEFI Secure Boot verification before execution | Regress the historical signed/unsigned/wrong-key/modified controls |
| Modify root/tree, including coherent substitution | Expected authority in signed UKI; full preverification and runtime dm-verity | Regress all four historical root controls |
| Supply malformed/traversing/symlinked public inputs | Explicit path allowlists, pinned manifests, regular-file checks, no reference code execution | Offline tests and verified import |
| Accidentally start/reset wrong device | Validated ID, exclusive device lock, explicit creation, local per-run QMP | No host disk/TPM access or implicit new-device operation |
| Replay or interrupt an update | Authorized RAUC, inactive-slot writes, finite trials, recovery/security epoch | Future phases; not implemented here |
| Move encrypted disk to another device | TPM2 policy and independent per-device LUKS material | Future Phase 5; swtpm attachment alone is not proof |
| Replay attestation or impersonate a device | Enrolled AK, fresh challenge, quote/log/allowlist verification | Future Phase 8 |
| Use recovery to bypass normal policy | Restricted signed recovery and one-time operation/device authorization | Future Phase 9 |
| Modify initial physical firmware or abuse SPI/UART/USB | FireArc root ownership, verified regions, flash protections and controlled recovery | Pending hardware; historical fixture has vboot disabled |

## Non-negotiable failure behavior

- Never retry an unverified raw root, unsigned UKI or unrestricted initrd shell.
- A boot failure is not permission to reformat, clear the TPM, reset NVRAM,
  regenerate keys or change the expected digest.
- Readiness is not attestation, and host termination after firmware denial is not
  automatic rollback.
- Writable encrypted data is not automatically authenticated configuration; do
  not place trusted executables, units or trust roots under general `/data`.
- Keep normal data unlock/local rollback independent of network availability.
- A filesystem rename or VM process kill alone does not prove FAT/SSD/flash
  power-loss atomicity. It needs a defined fault model and hardware testing.

## Current runner boundary

The research runner has no VM NIC, host mounts, host TPM passthrough or host
block-device write. It uses imported public raw images and per-device writable
flash/qcow2 overlays. Only the pinned SMMSTORE region may differ from the imported
firmware. All ordinary runs preserve those device files. Negative disk mutations
are made on per-run copies, never on the imported baseline or reference checkout.

`run/` and `artifacts/` are ignored and 0700. Software-TPM state is private even
in a lab. Evidence may record public hashes/commands, but never export TPM blobs,
recovery credentials, private signing keys or captured support sessions.

## Further analysis required

Firmware/vboot/SMMSTORE composition, protected revocation, exact systemd PCR
phase policies, UKI external inputs, shared-FAT availability, pre-Linux fallback,
data migration and key rotations are still blocking design/test work. Runtime
root compromise, DMA, cold-boot and TPM-bus attacks need separate assessment;
Secure Boot/LUKS do not eliminate them.

See [risks](risks.md). Owner/security review of this initial model is pending.
